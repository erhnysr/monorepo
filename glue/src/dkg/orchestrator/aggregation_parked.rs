//! Parked recovery for one aggregation epoch.
//!
//! A parked epoch has no aggregation engine. This operation replays its exact
//! journal into durable history, schedules a bounded batch of missing
//! certificates, and destroys the journal only after history authorizes the
//! exact retirement.

use super::aggregation::{
    ArchiveStatus, Cleanup, Handler, Provider, RequestError, Retirement,
};
use commonware_codec::Encode as _;
use commonware_consensus::{
    aggregation::{
        Journal, JournalConfig, JournalError, Recoverer, scheme::Scheme, types::RecoveryKey,
    },
    types::Height,
};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_runtime::{Metrics, Storage};
use rand_core::CryptoRng;
use std::num::NonZeroUsize;
use thiserror::Error;

/// Result of one parked recovery pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The epoch still has missing certificates or lacks cleanup authorization.
    Parked,
    /// Durable history is complete and the exact journal was destroyed.
    Retired,
}

/// Error encountered while recovering a parked epoch.
#[derive(Debug, Error)]
pub enum Error {
    /// The journal could not be opened, verified, or destroyed.
    #[error("aggregation journal error: {0}")]
    Journal(#[from] JournalError),
    /// Authenticated history does not contain the journal's epoch.
    #[error("aggregation epoch is absent from authenticated history")]
    UnknownEpoch,
    /// Authenticated history assigns a different range to the epoch.
    #[error("aggregation journal range differs from authenticated history")]
    RangeMismatch,
    /// Durable history rejected a certificate verified from the exact journal.
    #[error("aggregation history rejected the journal certificate at {0}")]
    HistoryRejected(Height),
    /// History authorized cleanup for a different range.
    #[error("aggregation history returned mismatched cleanup authorization")]
    CleanupMismatch,
    /// The bounded history ingress could not accept this recovery pass.
    #[error("aggregation history is backpressured")]
    HistoryBackpressured,
    /// The durable history actor is closed.
    #[error("aggregation history is unavailable")]
    HistoryUnavailable,
    /// The recovery scheduler is closed.
    #[error("aggregation recovery scheduler is closed")]
    RecovererClosed,
}

/// Runs one bounded recovery pass for a parked aggregation epoch.
///
/// Backpressure ends the bounded pass so its caller can retry later. A closed
/// history actor is fatal. The function never constructs or starts an
/// aggregation engine.
#[allow(clippy::too_many_arguments)]
pub async fn recover<E, S, D, P, V, R, T>(
    storage: E,
    journal_config: JournalConfig,
    provider: &P,
    verifier: &mut V,
    scheme: &S,
    strategy: &T,
    history: &mut Handler,
    recoverer: &mut R,
    missing_batch: NonZeroUsize,
) -> Result<Outcome, Error>
where
    E: Storage + Metrics,
    S: Scheme<D>,
    D: Digest,
    P: Provider<S>,
    V: CryptoRng,
    R: Recoverer,
    T: Strategy,
{
    let identity = &journal_config.identity;
    let Some(epoch) = provider.epoch(identity.namespace, identity.epoch) else {
        return Err(Error::UnknownEpoch);
    };
    if epoch.first() != identity.first || epoch.last() != identity.last {
        return Err(Error::RangeMismatch);
    }

    let (journal, certificates) =
        Journal::<E, S, D>::init(storage, journal_config, verifier, scheme, strategy).await?;
    let identity = journal.identity();
    let retirement = Retirement {
        namespace: identity.namespace,
        epoch: identity.epoch,
        first: identity.first,
        last: identity.last,
    };

    for certificate in certificates {
        let position = certificate.item.position;
        let key = RecoveryKey {
            namespace: retirement.namespace,
            epoch: retirement.epoch,
            position,
        };
        match history.archive(key, certificate.encode()).await {
            Ok(ArchiveStatus::Stored | ArchiveStatus::Duplicate) => {}
            Ok(ArchiveStatus::Rejected) => return Err(Error::HistoryRejected(position)),
            Err(RequestError::Backpressured) => return Err(Error::HistoryBackpressured),
            Err(RequestError::Closed) => return Err(Error::HistoryUnavailable),
        }
    }

    let missing = match history.missing(retirement, missing_batch).await {
        Ok(missing) => missing,
        Err(RequestError::Backpressured) => return Err(Error::HistoryBackpressured),
        Err(RequestError::Closed) => return Err(Error::HistoryUnavailable),
    };
    if !missing.is_empty() {
        for position in missing {
            let key = RecoveryKey {
                namespace: retirement.namespace,
                epoch: retirement.epoch,
                position,
            };
            if recoverer.fetch(key) == commonware_actor::Feedback::Closed {
                return Err(Error::RecovererClosed);
            }
        }
        return Ok(Outcome::Parked);
    }

    let cleanup = match history.retire(retirement).await {
        Ok(cleanup) => cleanup,
        Err(RequestError::Backpressured) => return Err(Error::HistoryBackpressured),
        Err(RequestError::Closed) => return Err(Error::HistoryUnavailable),
    };
    match cleanup {
        Some(Cleanup {
            retirement: authorized,
        }) if authorized == retirement => {
            journal.destroy().await?;
            Ok(Outcome::Retired)
        }
        Some(_) => Err(Error::CleanupMismatch),
        None => Ok(Outcome::Parked),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::orchestrator::aggregation::{
        Actor as HistoryActor, AuthenticatedEpoch, Config as HistoryConfig,
    };
    use commonware_actor::Feedback;
    use commonware_codec::Read;
    use commonware_consensus::{
        aggregation::{
            JournalIdentity, scheme,
            types::{Ack, Certificate, Item, RecoveryNamespace},
        },
        types::Epoch,
    };
    use commonware_cryptography::{Hasher as _, Sha256, certificate::Verifier as _};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{archive::immutable, metadata};
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty, sync::Mutex};
    use std::{collections::BTreeMap, num::NonZeroU64, sync::Arc};

    type TestScheme = scheme::ed25519::Scheme;
    type TestDigest = commonware_cryptography::sha256::Digest;

    #[derive(Clone)]
    struct TestProvider {
        namespace: RecoveryNamespace,
        epochs: Arc<BTreeMap<Epoch, AuthenticatedEpoch<TestScheme>>>,
    }

    impl Provider<TestScheme> for TestProvider {
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

    #[derive(Clone, Default)]
    struct RecordingRecoverer(Arc<Mutex<Vec<RecoveryKey>>>);

    impl Recoverer for RecordingRecoverer {
        fn fetch(&mut self, key: RecoveryKey) -> Feedback {
            self.0.lock().push(key);
            Feedback::Ok
        }

        fn cancel(&mut self, _: RecoveryKey) -> Feedback {
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct ClosedRecoverer;

    impl Recoverer for ClosedRecoverer {
        fn fetch(&mut self, _: RecoveryKey) -> Feedback {
            Feedback::Closed
        }

        fn cancel(&mut self, _: RecoveryKey) -> Feedback {
            Feedback::Closed
        }
    }

    fn provider(
        namespace: RecoveryNamespace,
        scheme: Arc<TestScheme>,
        epoch: Epoch,
        first: Height,
        last: Height,
    ) -> TestProvider {
        let mut epochs = BTreeMap::new();
        epochs.insert(epoch, AuthenticatedEpoch::new(scheme, first, last).unwrap());
        TestProvider {
            namespace,
            epochs: Arc::new(epochs),
        }
    }

    fn history_config(
        context: &deterministic::Context,
        namespace: RecoveryNamespace,
        codec_config: <<TestScheme as commonware_cryptography::certificate::Verifier>::Certificate as Read>::Cfg,
        suffix: &str,
    ) -> HistoryConfig<
        <<TestScheme as commonware_cryptography::certificate::Verifier>::Certificate as Read>::Cfg,
    > {
        HistoryConfig {
            namespace,
            archive: immutable::Config {
                metadata_partition: format!("parked_archive_metadata_{suffix}"),
                freezer_table_partition: format!("parked_archive_table_{suffix}"),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 32,
                freezer_key_partition: format!("parked_archive_keys_{suffix}"),
                freezer_key_page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
                freezer_value_partition: format!("parked_archive_values_{suffix}"),
                freezer_value_target_size: 1024 * 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("parked_archive_ordinal_{suffix}"),
                items_per_section: NZU64!(64),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config,
            },
            metadata: metadata::Config {
                partition: format!("parked_retirement_{suffix}"),
                codec_config: (),
            },
            mailbox_size: NZUsize!(8),
        }
    }

    fn journal_config(
        context: &deterministic::Context,
        scheme: &TestScheme,
        partition: &str,
        epoch: Epoch,
        first: Height,
        last: Height,
    ) -> JournalConfig {
        JournalConfig {
            identity: JournalIdentity::new::<TestScheme, TestDigest>(
                scheme,
                epoch,
                first,
                last,
                NonZeroU64::new(2).unwrap(),
            ),
            partition: partition.into(),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
            heights_per_section: NZU64!(4),
            compression: None,
            page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
        }
    }

    fn certificate(
        schemes: &[TestScheme],
        epoch: Epoch,
        position: Height,
    ) -> Certificate<TestScheme, TestDigest> {
        let item = Item {
            position,
            digest: Sha256::hash(&[&position.get().to_be_bytes()]),
        };
        let acks: Vec<_> = schemes
            .iter()
            .filter_map(|scheme| Ack::sign(scheme, item.clone()))
            .collect();
        Certificate::from_acks(&schemes[0], epoch, non_empty![@acks.iter()], &Sequential).unwrap()
    }

    #[test_traced]
    fn schedules_bounded_missing_and_preserves_exact_journal() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"parked-missing", 4);
            let schemes = fixture.schemes;
            let scheme = Arc::new(schemes[0].clone());
            let namespace = <TestScheme as Scheme<TestDigest>>::recovery_namespace(&scheme);
            let epoch = Epoch::new(1);
            let first = Height::new(10);
            let last = Height::new(12);
            let provider = provider(namespace, scheme.clone(), epoch, first, last);
            let (history_actor, mut history) =
                HistoryActor::<_, TestScheme, TestDigest, _, _>::init(
                    context.child("history"),
                    history_config(
                        &context,
                        namespace,
                        schemes[0].certificate_codec_config(),
                        "missing",
                    ),
                    provider.clone(),
                    Sequential,
                )
                .await
                .unwrap();
            let history_task = history_actor.start();
            let config = journal_config(
                &context,
                &schemes[0],
                "parked_missing_journal",
                epoch,
                first,
                last,
            );
            let mut recoverer = RecordingRecoverer::default();
            let requests = recoverer.0.clone();
            assert_eq!(
                recover::<_, TestScheme, TestDigest, _, _, _, _>(
                    context.child("recover"),
                    config.clone(),
                    &provider,
                    &mut context,
                    &schemes[0],
                    &Sequential,
                    &mut history,
                    &mut recoverer,
                    NZUsize!(2),
                )
                .await
                .unwrap(),
                Outcome::Parked
            );
            assert_eq!(
                requests.lock().as_slice(),
                &[
                    RecoveryKey {
                        namespace,
                        epoch,
                        position: first
                    },
                    RecoveryKey {
                        namespace,
                        epoch,
                        position: Height::new(11)
                    },
                ]
            );

            let mut mismatch = config;
            mismatch.identity.epoch = Epoch::new(2);
            let reopened = Journal::<_, TestScheme, TestDigest>::init(
                context.child("mismatch"),
                mismatch,
                &mut context,
                &schemes[0],
                &Sequential,
            )
            .await;
            assert!(matches!(reopened, Err(JournalError::EpochMismatch)));

            context.child("stop").stop(0, None).await.unwrap();
            history_task.await.unwrap().unwrap();
        });
    }

    #[test_traced]
    fn destroys_journal_only_after_exact_durable_retirement() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"parked-retire", 4);
            let schemes = fixture.schemes;
            let scheme = Arc::new(schemes[0].clone());
            let namespace = <TestScheme as Scheme<TestDigest>>::recovery_namespace(&scheme);
            let epoch = Epoch::new(1);
            let position = Height::new(20);
            let provider = provider(namespace, scheme, epoch, position, position);
            let (history_actor, mut history) =
                HistoryActor::<_, TestScheme, TestDigest, _, _>::init(
                    context.child("history"),
                    history_config(
                        &context,
                        namespace,
                        schemes[0].certificate_codec_config(),
                        "retire",
                    ),
                    provider.clone(),
                    Sequential,
                )
                .await
                .unwrap();
            let history_task = history_actor.start();
            let key = RecoveryKey {
                namespace,
                epoch,
                position,
            };
            assert_eq!(
                history
                    .archive(key, certificate(&schemes, epoch, position).encode())
                    .await
                    .unwrap(),
                ArchiveStatus::Stored
            );
            let config = journal_config(
                &context,
                &schemes[0],
                "parked_retire_journal",
                epoch,
                position,
                position,
            );
            assert_eq!(
                recover::<_, TestScheme, TestDigest, _, _, _, _>(
                    context.child("recover"),
                    config.clone(),
                    &provider,
                    &mut context,
                    &schemes[0],
                    &Sequential,
                    &mut history,
                    &mut RecordingRecoverer::default(),
                    NZUsize!(1),
                )
                .await
                .unwrap(),
                Outcome::Retired
            );
            let retirement = Retirement {
                namespace,
                epoch,
                first: position,
                last: position,
            };
            assert!(history.retired(retirement).await.unwrap());

            let mut replacement = config;
            replacement.identity.epoch = Epoch::new(2);
            let (journal, certificates) = Journal::<_, TestScheme, TestDigest>::init(
                context.child("replacement"),
                replacement,
                &mut context,
                &schemes[0],
                &Sequential,
            )
            .await
            .unwrap();
            assert!(certificates.is_empty());
            journal.destroy().await.unwrap();

            context.child("stop").stop(0, None).await.unwrap();
            history_task.await.unwrap().unwrap();
        });
    }

    #[test_traced]
    fn rejects_unknown_epoch_and_range_mismatch_before_opening_journal() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"parked-errors", 1);
            let scheme = Arc::new(fixture.schemes[0].clone());
            let namespace = <TestScheme as Scheme<TestDigest>>::recovery_namespace(&scheme);
            let first = Height::new(30);
            let config = journal_config(
                &context,
                &fixture.schemes[0],
                "parked_error_journal",
                Epoch::new(1),
                first,
                first,
            );
            let absent = TestProvider {
                namespace,
                epochs: Arc::new(BTreeMap::new()),
            };
            // Use a real handler whose actor need not run: both errors precede any history request.
            let (history_actor, mut handler) =
                HistoryActor::<_, TestScheme, TestDigest, _, _>::init(
                    context.child("history"),
                    history_config(
                        &context,
                        namespace,
                        fixture.schemes[0].certificate_codec_config(),
                        "errors",
                    ),
                    absent.clone(),
                    Sequential,
                )
                .await
                .unwrap();
            drop(history_actor);
            assert!(matches!(
                recover::<_, TestScheme, TestDigest, _, _, _, _>(
                    context.child("unknown"),
                    config.clone(),
                    &absent,
                    &mut context,
                    &fixture.schemes[0],
                    &Sequential,
                    &mut handler,
                    &mut RecordingRecoverer::default(),
                    NZUsize!(1),
                )
                .await,
                Err(Error::UnknownEpoch)
            ));

            let mismatched = provider(namespace, scheme, Epoch::new(1), first, Height::new(31));
            assert!(matches!(
                recover::<_, TestScheme, TestDigest, _, _, _, _>(
                    context.child("range"),
                    config,
                    &mismatched,
                    &mut context,
                    &fixture.schemes[0],
                    &Sequential,
                    &mut handler,
                    &mut RecordingRecoverer::default(),
                    NZUsize!(1),
                )
                .await,
                Err(Error::RangeMismatch)
            ));
        });
    }

    #[test_traced]
    fn reports_closed_history_and_recovery_scheduler() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme::ed25519::fixture(&mut context, b"parked-closed", 1);
            let scheme = Arc::new(fixture.schemes[0].clone());
            let namespace = <TestScheme as Scheme<TestDigest>>::recovery_namespace(&scheme);
            let epoch = Epoch::new(1);
            let position = Height::new(40);
            let provider = provider(namespace, scheme, epoch, position, position);
            let (closed_actor, mut closed_history) =
                HistoryActor::<_, TestScheme, TestDigest, _, _>::init(
                    context.child("closed_history"),
                    history_config(
                        &context,
                        namespace,
                        fixture.schemes[0].certificate_codec_config(),
                        "closed",
                    ),
                    provider.clone(),
                    Sequential,
                )
                .await
                .unwrap();
            drop(closed_actor);
            assert!(matches!(
                recover::<_, TestScheme, TestDigest, _, _, _, _>(
                    context.child("closed_recover"),
                    journal_config(
                        &context,
                        &fixture.schemes[0],
                        "parked_closed_history_journal",
                        epoch,
                        position,
                        position,
                    ),
                    &provider,
                    &mut context,
                    &fixture.schemes[0],
                    &Sequential,
                    &mut closed_history,
                    &mut RecordingRecoverer::default(),
                    NZUsize!(1),
                )
                .await,
                Err(Error::HistoryUnavailable)
            ));

            let (history_actor, mut history) =
                HistoryActor::<_, TestScheme, TestDigest, _, _>::init(
                    context.child("active_history"),
                    history_config(
                        &context,
                        namespace,
                        fixture.schemes[0].certificate_codec_config(),
                        "scheduler",
                    ),
                    provider.clone(),
                    Sequential,
                )
                .await
                .unwrap();
            let task = history_actor.start();
            assert!(matches!(
                recover::<_, TestScheme, TestDigest, _, _, _, _>(
                    context.child("scheduler_recover"),
                    journal_config(
                        &context,
                        &fixture.schemes[0],
                        "parked_closed_scheduler_journal",
                        epoch,
                        position,
                        position,
                    ),
                    &provider,
                    &mut context,
                    &fixture.schemes[0],
                    &Sequential,
                    &mut history,
                    &mut ClosedRecoverer,
                    NZUsize!(1),
                )
                .await,
                Err(Error::RecovererClosed)
            ));
            context.child("stop").stop(0, None).await.unwrap();
            task.await.unwrap().unwrap();
        });
    }
}
