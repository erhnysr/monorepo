//! Routes durably archived aggregation certificates to active epoch engines.

use super::aggregation::{self as history, Provider as HistoryProvider};
use bytes::Bytes;
use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{self, UnreliablePolicy, UnreliableSender},
};
use commonware_codec::Decode;
use commonware_consensus::{
    aggregation::{
        CertificateOutcome, Mailbox, Recoverer,
        scheme::Scheme,
        types::{Certificate, RecoveryKey, RecoveryNamespace},
    },
    types::Epoch,
};
use commonware_cryptography::{Digest, certificate::Provider as SchemeProvider};
use commonware_macros::select;
use commonware_resolver::{Consumer, Delivery, Outcome};
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::channel::oneshot;
use std::{
    collections::{BTreeMap, VecDeque},
    marker::PhantomData,
    num::NonZeroUsize,
};

type Scope = (RecoveryNamespace, Epoch);

struct DeliveryResponse(Option<oneshot::Sender<Outcome>>);

impl DeliveryResponse {
    const fn new(response: oneshot::Sender<Outcome>) -> Self {
        Self(Some(response))
    }

    fn send(mut self, outcome: Outcome) {
        let _ = self
            .0
            .take()
            .expect("delivery response missing")
            .send(outcome);
    }
}

impl Drop for DeliveryResponse {
    fn drop(&mut self) {
        if let Some(response) = self.0.take() {
            let _ = response.send(Outcome::Ignored);
        }
    }
}

enum Message<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    Register {
        scope: Scope,
        mailbox: Mailbox<S, D>,
    },
    Unregister {
        scope: Scope,
    },
    Deliver {
        delivery: Delivery<RecoveryKey, ()>,
        value: Bytes,
        response: DeliveryResponse,
    },
}

impl<S, D> UnreliablePolicy for Message<S, D>
where
    S: commonware_cryptography::certificate::Scheme,
    D: Digest,
{
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut Self::Overflow, message: Self) -> bool {
        if let Self::Deliver { response, .. } = message {
            response.send(Outcome::Ambiguous);
        }
        false
    }
}

/// Cloneable handle for registering active aggregation engines.
#[derive(Clone)]
pub struct Registry<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    sender: UnreliableSender<Message<S, D>>,
}

impl<S, D> Registry<S, D>
where
    S: commonware_cryptography::certificate::Scheme,
    D: Digest,
{
    /// Registers or replaces the active engine for `namespace` and `epoch`.
    #[must_use = "caller must retry rejected registry updates"]
    pub fn register(
        &mut self,
        namespace: RecoveryNamespace,
        epoch: Epoch,
        mailbox: Mailbox<S, D>,
    ) -> Unreliable<Feedback> {
        self.sender.enqueue(Message::Register {
            scope: (namespace, epoch),
            mailbox,
        })
    }

    /// Removes the active engine for `namespace` and `epoch`.
    #[must_use = "caller must retry rejected registry updates"]
    pub fn unregister(
        &mut self,
        namespace: RecoveryNamespace,
        epoch: Epoch,
    ) -> Unreliable<Feedback> {
        self.sender.enqueue(Message::Unregister {
            scope: (namespace, epoch),
        })
    }
}

/// Cloneable resolver consumer for aggregation certificates.
#[derive(Clone)]
pub struct Handler<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    sender: UnreliableSender<Message<S, D>>,
}

impl<S, D> Consumer for Handler<S, D>
where
    S: Scheme<D>,
    D: Digest,
{
    type Key = RecoveryKey;
    type Value = Bytes;
    type Subscriber = ();
    type Outcome = Outcome;

    fn deliver(
        &mut self,
        delivery: Delivery<Self::Key, Self::Subscriber>,
        value: Self::Value,
    ) -> oneshot::Receiver<Self::Outcome> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Deliver {
            delivery,
            value,
            response: DeliveryResponse::new(response),
        });
        receiver
    }
}

/// Bounded actor that archives resolver responses before routing them.
pub struct Actor<E, S, D, P, R>
where
    E: Spawner + Metrics,
    S: Scheme<D>,
    D: Digest,
    P: HistoryProvider<S> + SchemeProvider<Scope = Epoch, Scheme = S>,
    R: Recoverer,
{
    context: ContextCell<E>,
    history: history::Handler,
    provider: P,
    recoverer: R,
    receiver: mailbox::UnreliableReceiver<Message<S, D>>,
    routes: BTreeMap<Scope, Mailbox<S, D>>,
    _digest: PhantomData<D>,
}

impl<E, S, D, P, R> Actor<E, S, D, P, R>
where
    E: Spawner + Metrics,
    S: Scheme<D>,
    D: Digest,
    P: HistoryProvider<S> + SchemeProvider<Scope = Epoch, Scheme = S>,
    R: Recoverer,
{
    /// Creates a router and its resolver and registry handles.
    pub fn new(
        context: E,
        history: history::Handler,
        provider: P,
        recoverer: R,
        mailbox_size: NonZeroUsize,
    ) -> (Self, Handler<S, D>, Registry<S, D>) {
        let (sender, receiver) = mailbox::new_unreliable(context.child("mailbox"), mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                history,
                provider,
                recoverer,
                receiver,
                routes: BTreeMap::new(),
                _digest: PhantomData,
            },
            Handler {
                sender: sender.clone(),
            },
            Registry { sender },
        )
    }

    /// Starts the router actor.
    pub fn start(self) -> Handle<()> {
        let mut actor = self;
        spawn_cell!(actor.context, actor.run())
    }

    async fn run(mut self) {
        let mut shutdown = self.context.stopped();
        loop {
            let message = select! {
                _ = &mut shutdown => break,
                message = self.receiver.recv() => match message {
                    Some(message) => message,
                    None => break,
                },
            };

            match message {
                Message::Register { scope, mailbox } => {
                    self.routes.insert(scope, mailbox);
                }
                Message::Unregister { scope } => {
                    self.routes.remove(&scope);
                }
                Message::Deliver {
                    delivery,
                    value,
                    response,
                } => {
                    let routed = self.route(delivery, value, response);
                    select! {
                        _ = &mut shutdown => break,
                        _ = routed => {},
                    }
                }
            }
        }
    }

    async fn route(
        &mut self,
        delivery: Delivery<RecoveryKey, ()>,
        value: Bytes,
        response: DeliveryResponse,
    ) {
        let key = delivery.key;
        let history_outcome = self.history.deliver(delivery, value.clone()).await;
        match history_outcome {
            Ok(Outcome::Invalid) => {
                response.send(Outcome::Invalid);
                return;
            }
            Ok(Outcome::Complete) => {}
            Ok(Outcome::Ambiguous | Outcome::Ignored) | Err(_) => return,
        }

        let Some(mut mailbox) = self.routes.get(&(key.namespace, key.epoch)).cloned() else {
            let _ = self.recoverer.cancel(key);
            response.send(Outcome::Complete);
            return;
        };

        let Some(authenticated) = self.provider.epoch(key.namespace, key.epoch) else {
            response.send(Outcome::Ignored);
            return;
        };
        let Some(scheme) = self.provider.scheme(key.epoch) else {
            response.send(Outcome::Ignored);
            return;
        };
        if scheme.recovery_namespace() != key.namespace
            || key.position < authenticated.first()
            || key.position > authenticated.last()
        {
            response.send(Outcome::Invalid);
            return;
        }
        let Ok(certificate) =
            Certificate::<S, D>::decode_cfg(value, &scheme.certificate_codec_config())
        else {
            response.send(Outcome::Invalid);
            return;
        };
        if certificate.epoch != key.epoch || certificate.item.position != key.position {
            response.send(Outcome::Invalid);
            return;
        }

        match mailbox.submit(certificate).await {
            CertificateOutcome::Accepted | CertificateOutcome::Ignored => {
                let _ = self.recoverer.cancel(key);
                response.send(Outcome::Complete);
            }
            CertificateOutcome::Backpressured => response.send(Outcome::Ambiguous),
            CertificateOutcome::Invalid => response.send(Outcome::Invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::orchestrator::aggregation::{
        Actor as HistoryActor, AuthenticatedEpoch, Config as HistoryConfig,
    };
    use commonware_actor::Feedback;
    use commonware_codec::{Encode as _, Read};
    use commonware_consensus::aggregation::{
        scheme,
        types::{Ack, Item},
    };
    use commonware_cryptography::{
        Hasher as _, Sha256,
        certificate::{Scoped, Verifier as _},
    };
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_resolver::p2p::Producer as _;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{archive::immutable, metadata};
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty, non_empty_vec, sync::Mutex};
    use std::{collections::BTreeMap, sync::Arc};

    type TestScheme = scheme::ed25519::Scheme;
    type TestDigest = commonware_cryptography::sha256::Digest;

    #[derive(Clone)]
    struct TestProvider {
        namespace: RecoveryNamespace,
        epochs: Arc<BTreeMap<Epoch, AuthenticatedEpoch<TestScheme>>>,
        scheme: Arc<TestScheme>,
    }

    impl HistoryProvider<TestScheme> for TestProvider {
        fn epoch(
            &self,
            namespace: RecoveryNamespace,
            epoch: Epoch,
        ) -> Option<AuthenticatedEpoch<TestScheme>> {
            (namespace == self.namespace)
                .then(|| self.epochs.get(&epoch).cloned())
                .flatten()
        }

        fn oldest_epoch(&self, namespace: RecoveryNamespace) -> Option<Epoch> {
            (namespace == self.namespace).then_some(Epoch::new(1))
        }
    }

    impl SchemeProvider for TestProvider {
        type Scope = Epoch;
        type Scheme = TestScheme;

        fn scoped(&self, scope: Epoch) -> Option<Scoped<TestScheme>> {
            self.epochs
                .contains_key(&scope)
                .then(|| Scoped::scheme(self.scheme.clone()))
        }
    }

    #[derive(Clone, Default)]
    struct RecordingRecoverer(Arc<Mutex<Vec<RecoveryKey>>>);

    impl Recoverer for RecordingRecoverer {
        fn fetch(&mut self, _: RecoveryKey) -> commonware_actor::Unreliable<Feedback> {
            commonware_actor::Unreliable::new(Feedback::Ok)
        }

        fn cancel(&mut self, key: RecoveryKey) -> Feedback {
            self.0.lock().push(key);
            Feedback::Ok
        }
    }

    fn history_config(
        context: &deterministic::Context,
        namespace: RecoveryNamespace,
        codec_config: <<TestScheme as commonware_cryptography::certificate::Verifier>::Certificate as Read>::Cfg,
    ) -> HistoryConfig<
        <<TestScheme as commonware_cryptography::certificate::Verifier>::Certificate as Read>::Cfg,
    > {
        HistoryConfig {
            namespace,
            archive: immutable::Config {
                metadata_partition: "router_archive_metadata".into(),
                freezer_table_partition: "router_archive_table".into(),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 32,
                freezer_key_partition: "router_archive_keys".into(),
                freezer_key_page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
                freezer_value_partition: "router_archive_values".into(),
                freezer_value_target_size: 1024 * 1024,
                freezer_value_compression: None,
                ordinal_partition: "router_archive_ordinal".into(),
                items_per_section: NZU64!(64),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config,
            },
            metadata: metadata::Config {
                partition: "router_retirement".into(),
                codec_config: (),
            },
            mailbox_size: NZUsize!(8),
        }
    }

    fn key(namespace: RecoveryNamespace, position: u64) -> RecoveryKey {
        RecoveryKey {
            namespace,
            epoch: Epoch::new(1),
            position: commonware_consensus::types::Height::new(position),
        }
    }

    fn delivery(key: RecoveryKey) -> Delivery<RecoveryKey, ()> {
        Delivery {
            key,
            subscribers: non_empty_vec![((), tracing::Span::none())],
        }
    }

    #[test_traced]
    fn archives_before_completing_unrouted_delivery_and_rejects_invalid() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"aggregation-router", 4);
            let schemes = fixture.schemes;
            let scheme = Arc::new(schemes[0].clone());
            let namespace = <TestScheme as Scheme<TestDigest>>::recovery_namespace(&scheme);
            let position = commonware_consensus::types::Height::new(10);
            let mut epochs = BTreeMap::new();
            epochs.insert(
                Epoch::new(1),
                AuthenticatedEpoch::new(scheme.clone(), position, position).unwrap(),
            );
            let provider = TestProvider {
                namespace,
                epochs: Arc::new(epochs),
                scheme,
            };
            let (history_actor, mut history) =
                HistoryActor::<_, TestScheme, TestDigest, _, _>::init(
                    context.child("history"),
                    history_config(&context, namespace, schemes[0].certificate_codec_config()),
                    provider.clone(),
                    Sequential,
                )
                .await
                .unwrap();
            let history_task = history_actor.start();
            let recoverer = RecordingRecoverer::default();
            let canceled = recoverer.0.clone();
            let (router, mut handler, _registry) = Actor::<_, TestScheme, TestDigest, _, _>::new(
                context.child("router"),
                history.clone(),
                provider,
                recoverer,
                NZUsize!(8),
            );
            let router_task = router.start();

            let item = Item {
                position,
                digest: Sha256::hash(&[&position.get().to_be_bytes()]),
            };
            let acks: Vec<_> = schemes
                .iter()
                .filter_map(|scheme| Ack::sign(scheme, item.clone()))
                .collect();
            let certificate = Certificate::from_acks(
                &schemes[0],
                Epoch::new(1),
                non_empty![@acks.iter()],
                &Sequential,
            )
            .unwrap()
            .encode();
            let recovery_key = key(namespace, 10);
            assert_eq!(
                handler
                    .deliver(delivery(recovery_key), certificate.clone())
                    .await
                    .unwrap(),
                Outcome::Complete
            );
            assert_eq!(canceled.lock().as_slice(), &[recovery_key]);
            assert_eq!(history.produce(recovery_key).await.unwrap(), certificate);

            let invalid_key = key(namespace, 11);
            assert_eq!(
                handler
                    .deliver(delivery(invalid_key), Bytes::from_static(b"invalid"))
                    .await
                    .unwrap(),
                Outcome::Invalid
            );
            assert_eq!(canceled.lock().as_slice(), &[recovery_key]);

            context.child("stop").stop(0, None).await.unwrap();
            router_task.await.unwrap();
            history_task.await.unwrap().unwrap();
        });
    }

    #[test_traced]
    fn bounded_ingress_marks_overflowed_delivery_ambiguous() {
        deterministic::Runner::default().start(|context| async move {
            let (sender, _receiver) =
                mailbox::new_unreliable::<Message<TestScheme, TestDigest>>(context, NZUsize!(1));
            let mut handler = Handler {
                sender: sender.clone(),
            };
            let namespace = RecoveryNamespace::derive(b"router-backpressure");
            assert!(
                sender
                    .enqueue(Message::Unregister {
                        scope: (namespace, Epoch::new(1)),
                    })
                    .accepted()
            );
            assert_eq!(
                handler
                    .deliver(delivery(key(namespace, 1)), Bytes::new())
                    .await
                    .unwrap(),
                Outcome::Ambiguous
            );
        });
    }
}
