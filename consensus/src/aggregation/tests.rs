use super::{
    CertificateOutcome, Config, Engine,
    scheme::{self, Scheme},
    types::{Ack, Activity, Certificate, Item},
};
use crate::{
    Automaton, Reporter,
    types::{Epoch, Height},
};
use commonware_actor::Feedback;
use commonware_cryptography::{
    Hasher, Sha256,
    certificate::{Scheme as _, mocks::Fixture},
    ed25519::PublicKey,
    sha256::Digest as Sha256Digest,
};
use commonware_macros::test_traced;
use commonware_p2p::simulated::{Control, Link, Network, Oracle, Receiver, Sender};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock, Quota, Runner, Spawner as _, Supervisor as _,
    buffer::paged::CacheRef,
    deterministic::{self, Context},
};
use commonware_utils::{
    NZU16, NZUsize, NonZeroDuration,
    channel::oneshot,
    ordered::Quorum,
    probability,
    sync::Mutex,
};
use futures::future::join_all;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

const NAMESPACE: &[u8] = b"aggregation fixed epoch test";
const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
const QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);
const LINK: Link = Link {
    latency: Duration::from_millis(1),
    jitter: Duration::ZERO,
    success_rate: probability!(1.0),
};

type Registrations = BTreeMap<PublicKey, (Sender<PublicKey, Context>, Receiver<PublicKey>)>;

fn digest(position: Height) -> Sha256Digest {
    Sha256::hash(&[&position.get().to_be_bytes()])
}

#[derive(Clone, Default)]
struct ImmediateApplication {
    requested: Arc<Mutex<Vec<Height>>>,
}

impl Automaton for ImmediateApplication {
    type Context = Height;
    type Digest = Sha256Digest;

    async fn propose(&mut self, position: Height) -> oneshot::Receiver<Self::Digest> {
        self.requested.lock().push(position);
        let (sender, receiver) = oneshot::channel();
        sender.send(digest(position)).unwrap();
        receiver
    }

    async fn verify(
        &mut self,
        position: Height,
        candidate: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        sender.send(candidate == digest(position)).unwrap();
        receiver
    }
}

#[derive(Clone, Default)]
struct PendingApplication {
    requested: Arc<Mutex<BTreeMap<Height, oneshot::Sender<Sha256Digest>>>>,
}

impl Automaton for PendingApplication {
    type Context = Height;
    type Digest = Sha256Digest;

    async fn propose(&mut self, position: Height) -> oneshot::Receiver<Self::Digest> {
        let (sender, receiver) = oneshot::channel();
        assert!(self.requested.lock().insert(position, sender).is_none());
        receiver
    }

    async fn verify(
        &mut self,
        _position: Height,
        _candidate: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        sender.send(true).unwrap();
        receiver
    }
}

#[derive(Clone)]
struct RecordingReporter<S: commonware_cryptography::certificate::Scheme> {
    activities: Arc<Mutex<Vec<Activity<S, Sha256Digest>>>>,
}

impl<S: commonware_cryptography::certificate::Scheme> Default for RecordingReporter<S> {
    fn default() -> Self {
        Self {
            activities: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl<S: commonware_cryptography::certificate::Scheme> Reporter for RecordingReporter<S> {
    type Activity = Activity<S, Sha256Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.activities.lock().push(activity);
        Feedback::Ok
    }
}

async fn simulation<S: Scheme<Sha256Digest, PublicKey = PublicKey>>(
    context: Context,
    fixture: &Fixture<S>,
    connect: bool,
) -> (Oracle<PublicKey, Context>, Registrations) {
    let (network, oracle) = Network::new_with_peers(
        context.child("network"),
        commonware_p2p::simulated::Config {
            max_size: 1024 * 1024,
            max_peers_per_set: NZUsize!(fixture.participants.len()),
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        },
        fixture.participants.clone(),
    )
    .await;
    network.start();

    let mut registrations = BTreeMap::new();
    for participant in &fixture.participants {
        let registration = oracle
            .control(participant.clone())
            .register(0, QUOTA)
            .await
            .unwrap();
        registrations.insert(participant.clone(), registration);
    }
    if connect {
        for first in &fixture.participants {
            for second in &fixture.participants {
                if first != second {
                    oracle
                        .add_link(first.clone(), second.clone(), LINK.clone())
                        .await
                        .unwrap();
                }
            }
        }
    }
    (oracle, registrations)
}

struct EngineScope {
    partition: String,
    namespace: Vec<u8>,
    epoch: Epoch,
    first: Height,
    last: Height,
    window: u64,
}

fn config<S, A>(
    context: &Context,
    scheme: S,
    automaton: A,
    reporter: RecordingReporter<S>,
    blocker: Control<PublicKey, Context>,
    scope: EngineScope,
) -> Config<S, Sha256Digest, A, RecordingReporter<S>, Control<PublicKey, Context>, Sequential>
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    A: Automaton<Context = Height, Digest = Sha256Digest>,
{
    Config {
        namespace: scope.namespace,
        epoch: scope.epoch,
        first: scope.first,
        last: scope.last,
        scheme,
        automaton,
        reporter,
        blocker,
        priority_acks: false,
        rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_millis(50)),
        window: NonZeroU64::new(scope.window).unwrap(),
        journal_partition: scope.partition,
        journal_write_buffer: NZUsize!(4096),
        journal_replay_buffer: NZUsize!(4096),
        journal_heights_per_section: NonZeroU64::new(4).unwrap(),
        journal_compression: None,
        journal_page_cache: CacheRef::from_pooler(context, PAGE_SIZE, PAGE_CACHE_SIZE),
        strategy: Sequential,
    }
}

fn all_online<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: FnOnce(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(20)).start(|mut context| async move {
        let fixture = fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(7);
        let first = Height::new(10);
        let last = Height::new(25);
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, true).await;
        let mut handles = Vec::new();
        let mut observations = Vec::new();

        for (index, participant) in fixture.participants.iter().enumerate() {
            let child = context
                .child("validator")
                .with_attribute("index", index);
            let application = ImmediateApplication::default();
            let requested = application.requested.clone();
            let reporter = RecordingReporter::default();
            let activities = reporter.activities.clone();
            let cfg = config(
                &child,
                fixture.schemes[index].clone(),
                application,
                reporter,
                oracle.control(participant.clone()),
                EngineScope {
                    partition: format!("aggregation-{index}"),
                    namespace: NAMESPACE.to_vec(),
                    epoch,
                    first,
                    last,
                    window: 3,
                },
            );
            let (engine, _mailbox) = Engine::new(child.child("engine"), cfg);
            let network = registrations.remove(participant).unwrap();
            handles.push(engine.start(network));
            observations.push((requested, activities));
        }

        for result in join_all(handles).await {
            result.expect("aggregation engine failed");
        }
        for (requested, activities) in observations {
            let requested = requested.lock();
            assert_eq!(requested.len(), 16);
            assert!(requested.iter().all(|position| *position >= first && *position <= last));

            let activities = activities.lock();
            let certificates: BTreeMap<_, _> = activities
                .iter()
                .filter_map(|activity| match activity {
                    Activity::Certified(certificate) => {
                        Some((certificate.item.position, certificate))
                    }
                    Activity::Ack(_) => None,
                })
                .collect();
            assert_eq!(certificates.len(), 16);
            assert_eq!(certificates.first_key_value().unwrap().0, &first);
            assert_eq!(certificates.last_key_value().unwrap().0, &last);
        }
    });
}

#[test_traced("INFO")]
fn test_fixed_range_all_online() {
    all_online(scheme::ed25519::fixture);
}

fn certificate_ingress<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: FnOnce(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(9);
        let position = Height::new(50);
        let (oracle, mut registrations) =
            simulation(context.child("simulation"), &fixture, false).await;
        let participant = fixture.participants[0].clone();
        let application = PendingApplication::default();
        let requested = application.requested.clone();
        let reporter = RecordingReporter::default();
        let activities = reporter.activities.clone();
        let cfg = config(
            &context,
            fixture.schemes[0].clone(),
            application,
            reporter,
            oracle.control(participant.clone()),
            EngineScope {
                partition: "aggregation-ingress".into(),
                namespace: NAMESPACE.to_vec(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, mut mailbox) = Engine::new(context.child("engine"), cfg);
        let handle = engine.start(registrations.remove(&participant).unwrap());

        while !requested.lock().contains_key(&position) {
            context.sleep(Duration::from_millis(1)).await;
        }

        let item = Item {
            position,
            digest: digest(position),
        };
        let quorum = fixture.schemes[0].participants().quorum::<S::Faults>() as usize;
        let acks: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
            .collect();
        let certificate = Certificate::from_acks(
            &fixture.schemes[0],
            epoch,
            &acks,
            &Sequential,
        )
        .unwrap();

        let mut wrong_epoch = certificate.clone();
        wrong_epoch.epoch = epoch.next();
        assert_eq!(mailbox.submit(wrong_epoch).await, CertificateOutcome::Invalid);

        let mut outside = certificate.clone();
        outside.item.position = position.next();
        assert_eq!(mailbox.submit(outside).await, CertificateOutcome::Invalid);

        let mut invalid = certificate.clone();
        invalid.item.digest = Sha256::hash(&[b"invalid"]);
        assert_eq!(mailbox.submit(invalid).await, CertificateOutcome::Invalid);
        assert_eq!(mailbox.submit(certificate).await, CertificateOutcome::Accepted);
        handle.await.expect("aggregation engine failed");

        let pending_sender = requested.lock().remove(&position).unwrap();
        assert!(pending_sender.send(digest(position)).is_err());
        let activities = activities.lock();
        assert_eq!(
            activities
                .iter()
                .filter(|activity| matches!(activity, Activity::Certified(_)))
                .count(),
            1
        );
        assert!(!activities.iter().any(|activity| matches!(activity, Activity::Ack(_))));
    });
}

#[test_traced("INFO")]
fn test_certificate_ingress_cancels_digest() {
    certificate_ingress(scheme::ed25519::fixture);
}

#[test_traced("INFO")]
fn test_certificate_ingress_is_bounded() {
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = scheme::ed25519::fixture(&mut context, NAMESPACE, 4);
        let epoch = Epoch::new(10);
        let position = Height::new(60);
        let participant = fixture.participants[0].clone();
        let (oracle, _) = simulation(context.child("simulation"), &fixture, false).await;
        let cfg = config(
            &context,
            fixture.schemes[0].clone(),
            PendingApplication::default(),
            RecordingReporter::default(),
            oracle.control(participant),
            EngineScope {
                partition: "aggregation-bounded-ingress".into(),
                namespace: NAMESPACE.to_vec(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (engine, mut mailbox) = Engine::new(context.child("engine"), cfg);

        let item = Item {
            position,
            digest: digest(position),
        };
        let quorum = fixture.schemes[0]
            .participants()
            .quorum::<<scheme::ed25519::Scheme as commonware_cryptography::certificate::Verifier>::Faults>()
            as usize;
        let acks: Vec<_> = fixture
            .schemes
            .iter()
            .take(quorum)
            .map(|scheme| Ack::sign(scheme, item.clone()).unwrap())
            .collect();
        let certificate = Certificate::from_acks(
            &fixture.schemes[0],
            epoch,
            &acks,
            &Sequential,
        )
        .unwrap();

        let mut first_mailbox = mailbox.clone();
        let first_certificate = certificate.clone();
        let first = context.child("first_submit").spawn(move |_| async move {
            first_mailbox.submit(first_certificate).await
        });
        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(
            mailbox.submit(certificate).await,
            CertificateOutcome::Backpressured
        );

        drop(engine);
        assert_eq!(first.await.unwrap(), CertificateOutcome::Ignored);
    });
}

fn journal_identity<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: FnOnce(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = fixture(&mut context, NAMESPACE, 1);
        let participant = fixture.participants[0].clone();
        let epoch = Epoch::new(11);
        let position = Height::new(80);
        let partition = "aggregation-replay";

        let (first_oracle, mut first_registrations) =
            simulation(context.child("first_simulation"), &fixture, false).await;
        let first_reporter = RecordingReporter::default();
        let first_activities = first_reporter.activities.clone();
        let first_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            first_reporter,
            first_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                namespace: NAMESPACE.to_vec(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (first_engine, _mailbox) = Engine::new(context.child("first_engine"), first_cfg);
        first_engine
            .start(first_registrations.remove(&participant).unwrap())
            .await
            .expect("first aggregation engine failed");
        assert_eq!(
            first_activities
                .lock()
                .iter()
                .filter(|activity| matches!(activity, Activity::Certified(_)))
                .count(),
            1
        );

        let (second_oracle, mut second_registrations) =
            simulation(context.child("second_simulation"), &fixture, false).await;
        let replay_application = ImmediateApplication::default();
        let replay_requests = replay_application.requested.clone();
        let replay_reporter = RecordingReporter::default();
        let replay_activities = replay_reporter.activities.clone();
        let replay_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            replay_application,
            replay_reporter,
            second_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                namespace: NAMESPACE.to_vec(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (replay_engine, _mailbox) = Engine::new(context.child("replay_engine"), replay_cfg);
        replay_engine
            .start(second_registrations.remove(&participant).unwrap())
            .await
            .expect("replayed aggregation engine failed");
        assert!(replay_requests.lock().is_empty());
        assert_eq!(
            replay_activities
                .lock()
                .iter()
                .filter(|activity| matches!(activity, Activity::Certified(_)))
                .count(),
            1
        );

    });
}

#[test_traced("INFO")]
fn test_journal_replay_binds_engine_identity() {
    journal_identity(scheme::ed25519::fixture);
}

fn journal_identity_mismatch<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: FnOnce(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = fixture(&mut context, NAMESPACE, 1);
        let participant = fixture.participants[0].clone();
        let epoch = Epoch::new(12);
        let position = Height::new(90);
        let partition = "aggregation_identity_mismatch";

        let (first_oracle, mut first_registrations) =
            simulation(context.child("first_simulation"), &fixture, false).await;
        let first_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            first_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                namespace: NAMESPACE.to_vec(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (first_engine, _mailbox) = Engine::new(context.child("first_engine"), first_cfg);
        first_engine
            .start(first_registrations.remove(&participant).unwrap())
            .await
            .expect("first aggregation engine failed");

        let (mismatch_oracle, mut mismatch_registrations) =
            simulation(context.child("mismatch_simulation"), &fixture, false).await;
        let mismatch_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            mismatch_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                namespace: b"different namespace".to_vec(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (mismatch_engine, _mailbox) =
            Engine::new(context.child("mismatch_engine"), mismatch_cfg);
        let _ = mismatch_engine
            .start(mismatch_registrations.remove(&participant).unwrap())
            .await;
    });
}

#[test_traced("INFO")]
#[should_panic(expected = "aggregation journal namespace mismatch")]
fn test_journal_rejects_identity_mismatch() {
    journal_identity_mismatch(scheme::ed25519::fixture);
}

fn journal_window_mismatch<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: FnOnce(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let fixture = fixture(&mut context, NAMESPACE, 1);
        let participant = fixture.participants[0].clone();
        let epoch = Epoch::new(13);
        let position = Height::new(100);
        let partition = "aggregation_window_mismatch";

        let (first_oracle, mut first_registrations) =
            simulation(context.child("first_simulation"), &fixture, false).await;
        let first_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            first_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                namespace: NAMESPACE.to_vec(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (first_engine, _mailbox) = Engine::new(context.child("first_engine"), first_cfg);
        first_engine
            .start(first_registrations.remove(&participant).unwrap())
            .await
            .expect("first aggregation engine failed");

        let (mismatch_oracle, mut mismatch_registrations) =
            simulation(context.child("mismatch_simulation"), &fixture, false).await;
        let mismatch_cfg = config(
            &context,
            fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            mismatch_oracle.control(participant.clone()),
            EngineScope {
                partition: partition.into(),
                namespace: NAMESPACE.to_vec(),
                epoch,
                first: position,
                last: position,
                window: 2,
            },
        );
        let (mismatch_engine, _mailbox) =
            Engine::new(context.child("mismatch_engine"), mismatch_cfg);
        let _ = mismatch_engine
            .start(mismatch_registrations.remove(&participant).unwrap())
            .await;
    });
}

#[test_traced("INFO")]
#[should_panic(expected = "aggregation journal window mismatch")]
fn test_journal_rejects_window_mismatch() {
    journal_window_mismatch(scheme::ed25519::fixture);
}

fn journal_committee_mismatch<S, F>(fixture: F)
where
    S: Scheme<Sha256Digest, PublicKey = PublicKey>,
    F: Fn(&mut Context, &[u8], u32) -> Fixture<S>,
{
    deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
        let first_fixture = fixture(&mut context, NAMESPACE, 1);
        let first_participant = first_fixture.participants[0].clone();
        let epoch = Epoch::new(14);
        let position = Height::new(110);
        let partition = "aggregation_committee_mismatch";

        let (first_oracle, mut first_registrations) =
            simulation(context.child("first_simulation"), &first_fixture, false).await;
        let first_cfg = config(
            &context,
            first_fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            first_oracle.control(first_participant.clone()),
            EngineScope {
                partition: partition.into(),
                namespace: NAMESPACE.to_vec(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (first_engine, _mailbox) = Engine::new(context.child("first_engine"), first_cfg);
        first_engine
            .start(first_registrations.remove(&first_participant).unwrap())
            .await
            .expect("first aggregation engine failed");

        let second_fixture = fixture(&mut context, NAMESPACE, 1);
        let second_participant = second_fixture.participants[0].clone();
        let (mismatch_oracle, mut mismatch_registrations) = simulation(
            context.child("mismatch_simulation"),
            &second_fixture,
            false,
        )
        .await;
        let mismatch_cfg = config(
            &context,
            second_fixture.schemes[0].clone(),
            ImmediateApplication::default(),
            RecordingReporter::default(),
            mismatch_oracle.control(second_participant.clone()),
            EngineScope {
                partition: partition.into(),
                namespace: NAMESPACE.to_vec(),
                epoch,
                first: position,
                last: position,
                window: 1,
            },
        );
        let (mismatch_engine, _mailbox) =
            Engine::new(context.child("mismatch_engine"), mismatch_cfg);
        let _ = mismatch_engine
            .start(mismatch_registrations.remove(&second_participant).unwrap())
            .await;
    });
}

#[test_traced("INFO")]
#[should_panic(expected = "aggregation journal committee mismatch")]
fn test_journal_rejects_committee_mismatch() {
    journal_committee_mismatch(scheme::ed25519::fixture);
}
