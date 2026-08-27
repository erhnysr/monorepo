//! Fixed per-epoch aggregation engine.

use super::{
    Config, metrics, scheme,
    types::{Ack, Certificate, Error, Item},
};
use crate::{
    Automaton, Reporter,
    types::{Epoch, Height, Participant},
};
use bytes::{Buf, BufMut};
use commonware_actor::mailbox::{
    self, UnreliablePolicy, UnreliableReceiver as MailboxReceiver,
    UnreliableSender as MailboxSender,
};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{Digest, Hasher, Sha256, certificate::Verifier};
use commonware_macros::select;
use commonware_p2p::{
    Blocker, Receiver, Recipients, Sender,
    utils::codec::{WrappedSender, wrap},
};
use commonware_parallel::Strategy;
use commonware_runtime::{
    BufferPooler, Clock, ContextCell, Handle, Metrics as RuntimeMetrics, ReadOptions, Spawner,
    Storage,
    buffer::paged::CacheRef,
    spawn_cell,
    telemetry::metrics::{GaugeExt, histogram, status::Status},
};
use commonware_storage::journal::segmented::variable::{Config as JournalConfig, Journal};
use commonware_utils::{
    PrioritySet,
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool as FuturesPool, Aborter, rebind},
    non_empty,
    ordered::Quorum,
};
use futures::future::{self, Either};
use rand_core::CryptoRng;
use std::{
    collections::{BTreeMap, VecDeque},
    num::{NonZeroU64, NonZeroUsize},
    time::{Duration, SystemTime},
};
use tracing::{debug, info, warn};

const JOURNAL_VERSION: u8 = 2;
const JOURNAL_COMMITTEE_DOMAIN: &[u8] = b"_COMMONWARE_CONSENSUS_AGGREGATION_JOURNAL_COMMITTEE_V1";
type IdentityDigest = <Sha256 as Hasher>::Digest;

/// The first record binds all subsequent trusted records to one engine identity.
#[derive(Clone, Debug)]
struct Header {
    version: u8,
    committee: IdentityDigest,
    epoch: Epoch,
    first: Height,
    last: Height,
    window: u64,
}

impl Write for Header {
    fn write(&self, writer: &mut impl BufMut) {
        self.version.write(writer);
        self.committee.write(writer);
        self.epoch.write(writer);
        self.first.write(writer);
        self.last.write(writer);
        self.window.write(writer);
    }
}

impl Read for Header {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self {
            version: u8::read(reader)?,
            committee: IdentityDigest::read(reader)?,
            epoch: Epoch::read(reader)?,
            first: Height::read(reader)?,
            last: Height::read(reader)?,
            window: u64::read(reader)?,
        })
    }
}

impl EncodeSize for Header {
    fn encode_size(&self) -> usize {
        self.version.encode_size()
            + self.committee.encode_size()
            + self.epoch.encode_size()
            + self.first.encode_size()
            + self.last.encode_size()
            + self.window.encode_size()
    }
}

#[derive(Clone, Debug)]
enum Record<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    Header(Header),
    Certificate(Certificate<S, D>),
}

impl<S: commonware_cryptography::certificate::Scheme, D: Digest> Write for Record<S, D> {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Header(header) => {
                0u8.write(writer);
                header.write(writer);
            }
            Self::Certificate(certificate) => {
                1u8.write(writer);
                certificate.write(writer);
            }
        }
    }
}

impl<S: commonware_cryptography::certificate::Scheme, D: Digest> Read for Record<S, D> {
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        match u8::read(reader)? {
            0 => Ok(Self::Header(Header::read(reader)?)),
            1 => Ok(Self::Certificate(Certificate::read_cfg(reader, cfg)?)),
            _ => Err(CodecError::Invalid(
                "consensus::aggregation::Record",
                "invalid type",
            )),
        }
    }
}

impl<S: commonware_cryptography::certificate::Scheme, D: Digest> EncodeSize for Record<S, D> {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Header(v) => v.encode_size(),
            Self::Certificate(v) => v.encode_size(),
        }
    }
}

enum Pending<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    Unverified(BTreeMap<Participant, Ack<S, D>>),
    Verified(D, BTreeMap<Participant, Ack<S, D>>),
}

struct DigestRequest<D: Digest> {
    position: Height,
    result: Result<D, Error>,
    timer: histogram::Timer,
}

/// Result of submitting a recovered certificate to an active engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertificateOutcome {
    /// The certificate was valid and advanced local state.
    Accepted,
    /// The position was already certified or is no longer active.
    Ignored,
    /// The epoch, range, or signature was invalid.
    Invalid,
    /// The bounded ingress queue was full; the caller should retry later.
    Backpressured,
}

/// Reason an aggregation engine stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineOutcome {
    /// Every position in the configured range has a certificate.
    Completed,
    /// The engine stopped before certifying the full range.
    Stopped,
}

struct CertificateMessage<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    certificate: Certificate<S, D>,
    response: oneshot::Sender<CertificateOutcome>,
}

impl<S: commonware_cryptography::certificate::Scheme, D: Digest> UnreliablePolicy
    for CertificateMessage<S, D>
{
    type Overflow = VecDeque<Self>;

    fn handle(_: &mut Self::Overflow, _: Self) -> bool {
        false
    }
}

/// Delivers recovered certificates to an active engine.
#[derive(Clone)]
pub struct Mailbox<S: commonware_cryptography::certificate::Scheme, D: Digest> {
    sender: MailboxSender<CertificateMessage<S, D>>,
}

impl<S: commonware_cryptography::certificate::Scheme, D: Digest> Mailbox<S, D> {
    /// Validates and applies a recovered certificate.
    pub async fn submit(&mut self, certificate: Certificate<S, D>) -> CertificateOutcome {
        let (response, receiver) = oneshot::channel();
        if !self
            .sender
            .enqueue(CertificateMessage {
                certificate,
                response,
            })
            .accepted()
        {
            return CertificateOutcome::Backpressured;
        }
        receiver.await.unwrap_or(CertificateOutcome::Ignored)
    }
}

/// Aggregates every position in one immutable epoch and inclusive global range.
pub struct Engine<E, S, D, A, Z, B, T>
where
    E: BufferPooler + Clock + Spawner + Storage + RuntimeMetrics + CryptoRng,
    S: scheme::Scheme<D>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Certificate<S, D>>,
    B: Blocker<PublicKey = <S as Verifier>::PublicKey>,
    T: Strategy,
{
    context: ContextCell<E>,
    epoch: Epoch,
    first: Height,
    last: Height,
    scheme: S,
    automaton: A,
    reporter: Z,
    blocker: B,
    strategy: T,
    window: u64,
    frontier: Height,
    complete: bool,
    digest_requests: FuturesPool<'static, DigestRequest<D>>,
    digest_aborters: BTreeMap<Height, Aborter>,
    pending: BTreeMap<Height, Pending<S, D>>,
    confirmed: BTreeMap<Height, Certificate<S, D>>,
    rebroadcast_timeout: Duration,
    rebroadcast_deadlines: PrioritySet<Height, SystemTime>,
    journal: Option<Journal<E, Record<S, D>>>,
    journal_partition: String,
    journal_write_buffer: NonZeroUsize,
    journal_replay_buffer: NonZeroUsize,
    journal_heights_per_section: NonZeroU64,
    journal_compression: Option<u8>,
    journal_page_cache: CacheRef,
    priority_acks: bool,
    certificate_mailbox: MailboxReceiver<CertificateMessage<S, D>>,
    // Keep the mailbox open so its receive branch remains pending without external senders.
    _mailbox_keepalive: Mailbox<S, D>,
    metrics: metrics::Metrics,
}

impl<E, S, D, A, Z, B, T> Engine<E, S, D, A, Z, B, T>
where
    E: BufferPooler + Clock + Spawner + Storage + RuntimeMetrics + CryptoRng,
    S: scheme::Scheme<D>,
    D: Digest,
    A: Automaton<Context = Height, Digest = D>,
    Z: Reporter<Activity = Certificate<S, D>>,
    B: Blocker<PublicKey = <S as Verifier>::PublicKey>,
    T: Strategy,
{
    /// Creates an engine. Panics if the configured range is empty.
    pub fn new(context: E, cfg: Config<S, D, A, Z, B, T>) -> (Self, Mailbox<S, D>) {
        assert!(cfg.first <= cfg.last, "aggregation range must not be empty");
        let metrics = metrics::Metrics::init(&context);
        let mailbox_capacity = NonZeroUsize::new(
            usize::try_from(cfg.window.get()).expect("aggregation window exceeds usize"),
        )
        .expect("aggregation window must be non-zero");
        let (sender, certificate_mailbox) =
            mailbox::new_unreliable(context.child("mailbox"), mailbox_capacity);
        let mailbox = Mailbox { sender };
        let engine = Self {
            context: ContextCell::new(context),
            epoch: cfg.epoch,
            first: cfg.first,
            last: cfg.last,
            scheme: cfg.scheme,
            automaton: cfg.automaton,
            reporter: cfg.reporter,
            blocker: cfg.blocker,
            strategy: cfg.strategy,
            window: cfg.window.get(),
            frontier: cfg.first,
            complete: false,
            digest_requests: FuturesPool::default(),
            digest_aborters: BTreeMap::new(),
            pending: BTreeMap::new(),
            confirmed: BTreeMap::new(),
            rebroadcast_timeout: cfg.rebroadcast_timeout.into(),
            rebroadcast_deadlines: PrioritySet::new(),
            journal: None,
            journal_partition: cfg.journal_partition,
            journal_write_buffer: cfg.journal_write_buffer,
            journal_replay_buffer: cfg.journal_replay_buffer,
            journal_heights_per_section: cfg.journal_heights_per_section,
            journal_compression: cfg.journal_compression,
            journal_page_cache: cfg.journal_page_cache,
            priority_acks: cfg.priority_acks,
            certificate_mailbox,
            _mailbox_keepalive: mailbox.clone(),
            metrics,
        };
        (engine, mailbox)
    }

    /// Starts the engine and reports whether it completed or was stopped.
    pub fn start(
        self,
        network: (
            impl Sender<PublicKey = <S as Verifier>::PublicKey>,
            impl Receiver<PublicKey = <S as Verifier>::PublicKey>,
        ),
    ) -> Handle<EngineOutcome> {
        let mut this = self;
        spawn_cell!(this.context, this.run(network))
    }

    async fn run(
        mut self,
        network: (
            impl Sender<PublicKey = <S as Verifier>::PublicKey>,
            impl Receiver<PublicKey = <S as Verifier>::PublicKey>,
        ),
    ) -> EngineOutcome {
        let (mut sender, mut receiver) = wrap(
            (),
            self.context.network_buffer_pool().clone(),
            network.0,
            network.1,
        );
        self.init_journal().await;
        self.fill_window();
        let _ = self.metrics.frontier.try_set(self.frontier.get());
        let mut shutdown = self.context.stopped();
        // `select!` is biased, so alternate network and maintenance priority to prevent starvation.
        let mut network_first = true;
        let outcome = loop {
            if self.complete {
                break EngineOutcome::Completed;
            }
            let rebroadcast = match self.rebroadcast_deadlines.peek() {
                Some((_, &deadline)) => Either::Left(self.context.sleep_until(deadline)),
                None => Either::Right(future::pending()),
            };
            let maintenance = async {
                select! {
                    request = self.digest_requests.next_completed() => Either::Left(request),
                    _ = rebroadcast => Either::Right(Either::Left(())),
                    message = self.certificate_mailbox.recv() => Either::Right(Either::Right(message)),
                }
            };
            let event = if network_first {
                select! {
                    _ = &mut shutdown => { debug!("shutdown"); break EngineOutcome::Stopped; },
                    message = receiver.recv() => Either::Left(message),
                    maintenance = maintenance => Either::Right(maintenance),
                }
            } else {
                select! {
                    _ = &mut shutdown => { debug!("shutdown"); break EngineOutcome::Stopped; },
                    maintenance = maintenance => Either::Right(maintenance),
                    message = receiver.recv() => Either::Left(message),
                }
            };
            network_first = !network_first;

            match event {
                Either::Left(message) => {
                    let (peer, ack) = match message {
                        Ok(value) => value,
                        Err(err) => {
                            warn!(?err, "aggregation ack receiver failed");
                            break EngineOutcome::Stopped;
                        }
                    };
                    let mut guard = self.metrics.acks.guard(Status::Invalid);
                    let ack = match ack {
                        Ok(ack) => ack,
                        Err(err) => {
                            commonware_p2p::block!(self.blocker, peer, ?err, "ack decode failed");
                            continue;
                        }
                    };
                    if let Err(err) = self.validate_ack(&ack, &peer) {
                        if err.blockable() {
                            commonware_p2p::block!(
                                self.blocker,
                                peer,
                                ?err,
                                "ack validation failed"
                            );
                        }
                        continue;
                    }
                    if self.insert_ack(ack).await {
                        guard.set(Status::Success);
                    } else {
                        guard.set(Status::Failure);
                    }
                }
                Either::Right(Either::Left(request)) => {
                    let Ok(request) = request else {
                        continue;
                    };
                    let DigestRequest {
                        position,
                        result,
                        timer,
                    } = request;
                    self.digest_aborters.remove(&position);
                    match result {
                        Ok(digest) => {
                            timer.observe(self.context.as_ref());
                            self.handle_digest(position, digest, &mut sender).await;
                        }
                        Err(err) => {
                            warn!(?err, %position, "automaton returned error");
                            self.metrics.digest.inc(Status::Dropped);
                        }
                    }
                }
                Either::Right(Either::Right(Either::Left(()))) => {
                    let (position, _) = self
                        .rebroadcast_deadlines
                        .pop()
                        .expect("deadline disappeared");
                    self.rebroadcast(position, &mut sender);
                }
                Either::Right(Either::Right(Either::Right(message))) => {
                    let Some(CertificateMessage {
                        certificate,
                        response,
                    }) = message
                    else {
                        unreachable!("engine retains a certificate mailbox sender");
                    };
                    let outcome = self.handle_external_certificate(certificate).await;
                    response.send_lossy(outcome);
                }
            }
        };

        if let Some(journal) = self.journal.take() {
            journal
                .sync_all()
                .await
                .expect("unable to sync aggregation journal");
        }
        outcome
    }

    fn fill_window(&mut self) {
        if self.complete {
            return;
        }
        let end = self
            .frontier
            .get()
            .saturating_add(self.window - 1)
            .min(self.last.get());
        for raw in self.frontier.get()..=end {
            let position = Height::new(raw);
            if self.pending.contains_key(&position) || self.confirmed.contains_key(&position) {
                continue;
            }
            self.pending
                .insert(position, Pending::Unverified(BTreeMap::new()));
            self.request_digest(position);
        }
        debug_assert!(self.pending.len() + self.confirmed.len() <= self.window as usize);
    }

    fn request_digest(&mut self, position: Height) {
        assert!(!self.digest_aborters.contains_key(&position));
        let mut automaton = self.automaton.clone();
        let timer = self.metrics.digest_duration.timer(self.context.as_ref());
        let aborter = self.digest_requests.push(async move {
            let result = automaton
                .propose(position)
                .await
                .await
                .map_err(Error::AppProposeCanceled);
            DigestRequest {
                position,
                result,
                timer,
            }
        });
        assert!(self.digest_aborters.insert(position, aborter).is_none());
    }

    async fn handle_digest(
        &mut self,
        position: Height,
        digest: D,
        sender: &mut WrappedSender<impl Sender<PublicKey = <S as Verifier>::PublicKey>, Ack<S, D>>,
    ) {
        let shares = match self.pending.remove(&position) {
            Some(Pending::Unverified(shares)) => shares,
            Some(Pending::Verified(_, _)) => {
                unreachable!("digest completed for an already verified position")
            }
            None => return,
        };
        let matching = shares
            .into_iter()
            .filter(|(_, ack)| ack.item.digest == digest)
            .collect();
        self.pending
            .insert(position, Pending::Verified(digest, matching));
        let Some(ack) = Ack::sign(&self.scheme, Item { position, digest }) else {
            return;
        };
        self.rebroadcast_deadlines
            .put(position, self.context.current() + self.rebroadcast_timeout);
        sender.send(Recipients::All, ack.clone(), self.priority_acks);
        self.insert_ack(ack).await;
    }

    fn validate_ack(
        &mut self,
        ack: &Ack<S, D>,
        peer: &<S as Verifier>::PublicKey,
    ) -> Result<(), Error> {
        let position = ack.item.position;
        if position < self.first
            || position > self.last
            || !self.pending.contains_key(&position)
        {
            return Err(Error::AckPosition(position));
        }
        let Some(signer) = self.scheme.participants().index(peer) else {
            return Err(Error::PeerMismatch);
        };
        if signer != ack.attestation.signer {
            return Err(Error::PeerMismatch);
        }
        match self.pending.get(&position).expect("checked") {
            Pending::Verified(digest, shares) if *digest != ack.item.digest => {
                return Err(Error::AckDigest(position));
            }
            Pending::Verified(_, shares) | Pending::Unverified(shares)
                if shares.contains_key(&signer) =>
            {
                return Err(Error::AckDuplicate(peer.to_string(), position));
            }
            _ => {}
        }
        if !ack.verify(self.context.as_mut(), &self.scheme, &self.strategy) {
            return Err(Error::InvalidAckSignature);
        }
        Ok(())
    }

    async fn insert_ack(&mut self, ack: Ack<S, D>) -> bool {
        let position = ack.item.position;
        let Some(pending) = self.pending.get_mut(&position) else {
            return false;
        };
        let shares = match pending {
            Pending::Unverified(shares) => shares,
            Pending::Verified(digest, _) if *digest != ack.item.digest => return false,
            Pending::Verified(_, shares) => shares,
        };
        shares.entry(ack.attestation.signer).or_insert(ack.clone());
        let quorum = self.scheme.participants().quorum::<S::Faults>() as usize;
        let matching: Vec<_> = shares
            .values()
            .filter(|other| other.item.digest == ack.item.digest)
            .collect();
        if matching.len() < quorum {
            return true;
        }
        let certificate = Certificate::from_acks(
            &self.scheme,
            self.epoch,
            non_empty![@matching],
            &self.strategy,
        )
        .expect("verified signer-unique quorum must assemble");
        self.accept_certificate(certificate).await;
        true
    }

    async fn accept_certificate(&mut self, certificate: Certificate<S, D>) {
        let position = certificate.item.position;
        if certificate.epoch != self.epoch || position < self.frontier || position > self.last {
            return;
        }
        if let Some(existing) = self.confirmed.get(&position) {
            assert_eq!(
                existing.item.digest, certificate.item.digest,
                "conflicting certificates"
            );
            return;
        }
        self.record_certificate(certificate.clone()).await;
        self.reporter.report(certificate.clone());
        self.pending.remove(&position);
        self.digest_aborters.remove(&position);
        self.rebroadcast_deadlines.remove(&position);
        self.confirmed.insert(position, certificate);
        self.metrics.certificates.inc();
        while self.confirmed.remove(&self.frontier).is_some() {
            if self.frontier == self.last {
                self.complete = true;
                let _ = self.metrics.complete.try_set(1);
                break;
            }
            self.frontier = self.frontier.next();
        }
        let _ = self.metrics.frontier.try_set(self.frontier.get());
        self.fill_window();
    }

    async fn handle_external_certificate(
        &mut self,
        certificate: Certificate<S, D>,
    ) -> CertificateOutcome {
        let position = certificate.item.position;
        if certificate.epoch != self.epoch || position < self.first || position > self.last {
            return CertificateOutcome::Invalid;
        }
        if self.complete || position < self.frontier || self.confirmed.contains_key(&position) {
            return CertificateOutcome::Ignored;
        }
        if !self.pending.contains_key(&position) {
            return CertificateOutcome::Ignored;
        }
        if !certificate.verify_for(
            self.context.as_mut(),
            &self.scheme,
            self.epoch,
            self.first,
            self.last,
            &self.strategy,
        ) {
            return CertificateOutcome::Invalid;
        }
        self.accept_certificate(certificate).await;
        CertificateOutcome::Accepted
    }

    fn rebroadcast(
        &mut self,
        position: Height,
        sender: &mut WrappedSender<impl Sender<PublicKey = <S as Verifier>::PublicKey>, Ack<S, D>>,
    ) {
        let Some(me) = self.scheme.me() else {
            return;
        };
        let Some(Pending::Verified(_, shares)) = self.pending.get(&position) else {
            return;
        };
        let Some(ack) = shares.get(&me).cloned() else {
            return;
        };
        self.rebroadcast_deadlines
            .put(position, self.context.current() + self.rebroadcast_timeout);
        sender.send(Recipients::All, ack, self.priority_acks);
    }

    fn expected_header(&self) -> Header {
        let participants = self.scheme.participants().encode();
        let committee = Sha256::hash(&[JOURNAL_COMMITTEE_DOMAIN, participants.as_ref()]);
        Header {
            version: JOURNAL_VERSION,
            committee,
            epoch: self.epoch,
            first: self.first,
            last: self.last,
            window: self.window,
        }
    }

    async fn init_journal(&mut self) {
        let cfg = JournalConfig {
            partition: self.journal_partition.clone(),
            compression: self.journal_compression,
            codec_config: S::certificate_codec_config_unbounded(),
            page_cache: self.journal_page_cache.clone(),
            write_buffer: self.journal_write_buffer,
        };
        let journal = Journal::init(self.context.child("journal"), cfg)
            .await
            .expect("aggregation journal init failed");
        let empty = journal.is_empty();
        let mut replay = journal
            .replay(0, 0, self.journal_replay_buffer, ReadOptions::DONT_CACHE)
            .await
            .expect("aggregation journal replay failed");
        let expected = self.expected_header();
        let mut first_record = true;
        while let Some(record) = replay.next().await {
            let (_, _, _, record) = record.expect("corrupt aggregation journal");
            match (first_record, record) {
                (true, Record::Header(header)) => {
                    assert_eq!(
                        header.version, expected.version,
                        "aggregation journal version mismatch"
                    );
                    assert_eq!(
                        header.committee, expected.committee,
                        "aggregation journal committee mismatch"
                    );
                    assert_eq!(
                        header.epoch, expected.epoch,
                        "aggregation journal epoch mismatch"
                    );
                    assert_eq!(
                        header.first, expected.first,
                        "aggregation journal first-position mismatch"
                    );
                    assert_eq!(
                        header.last, expected.last,
                        "aggregation journal last-position mismatch"
                    );
                    assert_eq!(
                        header.window, expected.window,
                        "aggregation journal window mismatch; durably archive the complete range before replacing the journal"
                    );
                }
                (true, _) => panic!("aggregation journal header missing"),
                (false, Record::Header(_)) => panic!("duplicate aggregation journal header"),
                (false, Record::Certificate(certificate)) => {
                    self.replay_certificate(certificate)
                }
            }
            first_record = false;
        }
        let journal = replay.finish().expect("aggregation journal replay failed");
        if empty {
            assert!(first_record);
            let (journal, _, _) = journal
                .append(0, &Record::Header(expected))
                .await
                .expect("journal header append failed");
            self.journal = Some(journal.sync(0).await.expect("journal header sync failed"));
        } else {
            assert!(!first_record, "aggregation journal header missing");
            self.journal = Some(journal);
        }
        info!(epoch = %self.epoch, first = %self.first, last = %self.last, frontier = %self.frontier, "replayed aggregation journal");
    }

    fn replay_certificate(&mut self, certificate: Certificate<S, D>) {
        // The header does not bind all namespace and threshold-verifier material, so revalidate
        // every certificate.
        let position = certificate.item.position;
        assert_eq!(
            certificate.epoch, self.epoch,
            "journal certificate epoch mismatch"
        );
        assert!(
            position >= self.first && position <= self.last,
            "journal certificate outside range"
        );
        assert!(
            certificate.verify_for(
                self.context.as_mut(),
                &self.scheme,
                self.epoch,
                self.first,
                self.last,
                &self.strategy,
            ),
            "journal certificate signature mismatch"
        );
        if position >= self.frontier {
            if let Some(existing) = self.confirmed.insert(position, certificate.clone()) {
                assert_eq!(
                    existing.item.digest, certificate.item.digest,
                    "conflicting journal certificates"
                );
            }
            while self.confirmed.remove(&self.frontier).is_some() {
                if self.frontier == self.last {
                    self.complete = true;
                    let _ = self.metrics.complete.try_set(1);
                    break;
                }
                self.frontier = self.frontier.next();
            }
        }
        self.reporter.report(certificate);
    }

    async fn record_certificate(&mut self, certificate: Certificate<S, D>) {
        let position = certificate.item.position;
        let section = position.get() / self.journal_heights_per_section.get();
        let record = Record::Certificate(certificate);
        rebind(&mut self.journal, |journal| {
            journal.append(section, &record)
        })
        .await
        .expect("unable to append aggregation journal");
        rebind(&mut self.journal, |journal| journal.sync(section))
            .await
            .expect("unable to sync aggregation journal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregation::scheme::ed25519,
        simplex::mocks::wrapped::{Behavior, Scheme as WrappedScheme},
    };
    use commonware_actor::Feedback;
    use commonware_cryptography::{Sha256, certificate::mocks::Fixture};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZU16, NZUsize, NonZeroDuration};

    #[derive(Clone)]
    struct NoopAutomaton;

    impl Automaton for NoopAutomaton {
        type Context = Height;
        type Digest = <Sha256 as Hasher>::Digest;

        async fn propose(&mut self, _context: Height) -> oneshot::Receiver<Self::Digest> {
            oneshot::channel().1
        }

        async fn verify(
            &mut self,
            _context: Height,
            _digest: Self::Digest,
        ) -> oneshot::Receiver<bool> {
            oneshot::channel().1
        }
    }

    #[derive(Clone)]
    struct NoopReporter<S: commonware_cryptography::certificate::Scheme>(
        std::marker::PhantomData<S>,
    );

    impl<S: commonware_cryptography::certificate::Scheme> Reporter for NoopReporter<S> {
        type Activity = Certificate<S, <Sha256 as Hasher>::Digest>;

        fn report(&mut self, _activity: Self::Activity) -> Feedback {
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct NoopBlocker;

    impl Blocker for NoopBlocker {
        type PublicKey = commonware_cryptography::ed25519::PublicKey;

        fn block(&mut self, _peer: Self::PublicKey) -> Feedback {
            Feedback::Ok
        }
    }

    #[test]
    #[should_panic(expected = "verified signer-unique quorum must assemble")]
    fn assembly_failure_panics() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let Fixture { schemes, .. } =
                ed25519::fixture(&mut context, b"aggregation-recovery-failure", 4);
            let epoch = Epoch::new(111);
            let position = Height::new(0);
            let digest = Sha256::hash(&[b"payload"]);
            let scheme = WrappedScheme::new(schemes[0].clone(), Behavior::RecoveryFailure);
            let (mut engine, _) = Engine::new(
                context.child("engine"),
                Config {
                    epoch,
                    first: position,
                    last: position,
                    scheme,
                    automaton: NoopAutomaton,
                    reporter: NoopReporter(std::marker::PhantomData),
                    blocker: NoopBlocker,
                    priority_acks: false,
                    rebroadcast_timeout: NonZeroDuration::new_panic(Duration::from_secs(1)),
                    window: NonZeroU64::new(1).unwrap(),
                    journal_partition: "aggregation-recovery-failure".to_string(),
                    journal_write_buffer: NZUsize!(4096),
                    journal_replay_buffer: NZUsize!(4096),
                    journal_heights_per_section: NonZeroU64::new(4).unwrap(),
                    journal_compression: None,
                    journal_page_cache: CacheRef::from_pooler(
                        &context,
                        NZU16!(1024),
                        NZUsize!(10),
                    ),
                    strategy: Sequential,
                },
            );
            engine
                .pending
                .insert(position, Pending::Verified(digest, BTreeMap::new()));

            for scheme in schemes.iter().take(3) {
                let scheme = WrappedScheme::new(scheme.clone(), Behavior::Honest);
                let ack = Ack::sign(&scheme, Item { position, digest }).unwrap();
                assert!(engine.insert_ack(ack).await);
            }
        });
    }
}
