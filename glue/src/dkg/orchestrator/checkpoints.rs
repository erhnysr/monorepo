//! Durable finalized checkpoints for aggregation.
//!
//! Finalized blocks and aggregation proposals share one storage-owning actor.
//! A block acknowledgement is released only after its checkpoint is synced.

use commonware_actor::{
    Feedback,
    mailbox::{self, Overflow, Policy, Sender},
};
use commonware_codec::Read;
use commonware_consensus::{Automaton, Block, Reporter, marshal::Update, types::Height};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_storage::{
    Context,
    archive::{Archive as _, Identifier, immutable},
};
use commonware_utils::{Acknowledgement, channel::oneshot};
use std::{
    collections::{BTreeMap, VecDeque},
    marker::PhantomData,
    num::NonZeroUsize,
    sync::Arc,
};
use thiserror::Error;

/// A finalized block carrying the global checkpoint used by aggregation.
pub trait FinalizedBlock: Block {
    /// Checkpoint digest proposed for this block's global height.
    type Checkpoint: Digest;

    /// Returns the global height and its canonical checkpoint digest.
    ///
    /// The returned height must equal [`Heightable::height`](commonware_consensus::Heightable::height).
    fn finalized_checkpoint(&self) -> (Height, Self::Checkpoint);
}

/// Persistent checkpoint storage and ingress configuration.
pub struct Config<C> {
    /// Immutable archive indexed by global height.
    pub archive: immutable::Config<C>,
    /// Capacity of the primary ingress queue.
    ///
    /// Overflow is retained losslessly. Total retained ingress and waiter state is
    /// application-bounded: marshal holds finalized delivery behind the acknowledgement,
    /// and aggregation must use a finite live-height window and bounded request concurrency.
    pub mailbox_size: NonZeroUsize,
    /// Maximum unresolved proposal and verification requests.
    ///
    /// Configure at least the sum of all aggregation-engine windows that share
    /// this checkpoint store. Excess requests are declined by closing their response.
    pub max_pending_requests: NonZeroUsize,
}

/// Fatal checkpoint actor error.
#[derive(Debug, Error)]
pub enum Error {
    /// Immutable archive failure.
    #[error("checkpoint archive error: {0}")]
    Archive(#[from] commonware_storage::archive::Error),
    /// A height was finalized with a digest other than its durable canonical digest.
    #[error("conflicting finalized checkpoint at height {height}")]
    Conflict {
        /// Conflicting global height.
        height: Height,
    },
    /// The finalized-checkpoint height disagreed with the block height.
    #[error("checkpoint height {checkpoint} disagrees with block height {block}")]
    HeightMismatch {
        /// Height returned by [`FinalizedBlock`].
        checkpoint: Height,
        /// Height returned by the consensus block.
        block: Height,
    },
}

enum Request<D> {
    Propose(oneshot::Sender<D>),
    Verify(D, oneshot::Sender<bool>),
}

enum Message<B: FinalizedBlock, A: Acknowledgement> {
    Finalized(Arc<B>, A),
    Request {
        height: Height,
        request: Request<B::Checkpoint>,
        maximum: usize,
    },
}

struct Pending<B: FinalizedBlock, A: Acknowledgement> {
    messages: VecDeque<Message<B, A>>,
    requests: usize,
}

impl<B: FinalizedBlock, A: Acknowledgement> Default for Pending<B, A> {
    fn default() -> Self {
        Self {
            messages: VecDeque::new(),
            requests: 0,
        }
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> Overflow<Message<B, A>> for Pending<B, A> {
    fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<B, A>) -> Option<Message<B, A>>,
    {
        while let Some(message) = self.messages.pop_front() {
            let request = matches!(message, Message::Request { .. });
            if let Some(message) = push(message) {
                self.messages.push_front(message);
                break;
            }
            if request {
                self.requests -= 1;
            }
        }
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> Policy for Message<B, A> {
    type Overflow = Pending<B, A>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        if let Self::Request { maximum, .. } = &message {
            if overflow.requests >= *maximum {
                return;
            }
            overflow.requests += 1;
        }
        overflow.messages.push_back(message);
    }
}

/// Cloneable finalized-block reporter and aggregation automaton.
pub struct Handler<B: FinalizedBlock, A: Acknowledgement> {
    sender: Sender<Message<B, A>>,
    max_pending_requests: usize,
    _types: PhantomData<fn() -> (B, A)>,
}

impl<B: FinalizedBlock, A: Acknowledgement> Clone for Handler<B, A> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            max_pending_requests: self.max_pending_requests,
            _types: PhantomData,
        }
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> Reporter for Handler<B, A> {
    type Activity = Update<B, A>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block(block, acknowledgement) = activity else {
            return Feedback::Ok;
        };
        self.sender
            .enqueue(Message::Finalized(block, acknowledgement))
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> Automaton for Handler<B, A> {
    type Context = Height;
    type Digest = B::Checkpoint;

    async fn propose(&mut self, height: Height) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Request {
            height,
            request: Request::Propose(response),
            maximum: self.max_pending_requests,
        });
        receiver
    }

    async fn verify(&mut self, height: Height, digest: Self::Digest) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Request {
            height,
            request: Request::Verify(digest, response),
            maximum: self.max_pending_requests,
        });
        receiver
    }
}

type Archive<E, D> = immutable::Archive<E, D, D>;

/// Storage-owning finalized-checkpoint actor.
pub struct Actor<E, B, A>
where
    E: Context,
    B: FinalizedBlock,
    A: Acknowledgement,
{
    context: ContextCell<E>,
    archive: Option<Archive<E, B::Checkpoint>>,
    receiver: mailbox::Receiver<Message<B, A>>,
    waiters: BTreeMap<Height, Vec<Request<B::Checkpoint>>>,
    pending_requests: usize,
    max_pending_requests: usize,
}

impl<E, B, A> Actor<E, B, A>
where
    E: Context + Spawner,
    B: FinalizedBlock,
    A: Acknowledgement,
{
    /// Opens the durable archive and creates its application handle.
    pub async fn init(
        context: E,
        config: Config<<B::Checkpoint as Read>::Cfg>,
    ) -> Result<(Self, Handler<B, A>), Error> {
        let archive = immutable::Archive::init(context.child("archive"), config.archive).await?;
        let (sender, receiver) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        Ok((
            Self {
                context: ContextCell::new(context),
                archive: Some(archive),
                receiver,
                waiters: BTreeMap::new(),
                pending_requests: 0,
                max_pending_requests: config.max_pending_requests.get(),
            },
            Handler {
                sender,
                max_pending_requests: config.max_pending_requests.get(),
                _types: PhantomData,
            },
        ))
    }

    /// Starts the actor. Storage and consistency failures terminate it permanently.
    pub fn start(self) -> Handle<Result<(), Error>> {
        let mut actor = self;
        spawn_cell!(actor.context, actor.run())
    }

    async fn run(mut self) -> Result<(), Error> {
        select_loop! {
            self.context,
            on_stopped => {},
            Some(message) = self.receiver.recv() else break => match message {
                Message::Finalized(block, acknowledgement) => {
                    self.finalized(block, acknowledgement).await?;
                }
                Message::Request { height, request, .. } => self.request(height, request).await?,
            },
        }
        Ok(())
    }

    async fn request(
        &mut self,
        height: Height,
        request: Request<B::Checkpoint>,
    ) -> Result<(), Error> {
        let archive = self.archive.as_ref().expect("archive unavailable");
        if let Some(digest) = archive.get(Identifier::Index(height.get())).await? {
            Self::resolve(request, digest);
        } else if self.pending_requests == self.max_pending_requests {
            drop(request);
        } else {
            self.waiters.entry(height).or_default().push(request);
            self.pending_requests += 1;
        }
        Ok(())
    }

    async fn finalized(&mut self, block: Arc<B>, acknowledgement: A) -> Result<(), Error> {
        let block_height = block.height();
        let (height, digest) = block.finalized_checkpoint();
        if height != block_height {
            return Err(Error::HeightMismatch {
                checkpoint: height,
                block: block_height,
            });
        }

        let archive = self.archive.as_ref().expect("archive unavailable");
        if let Some(existing) = archive.get(Identifier::Index(height.get())).await? {
            if existing != digest {
                return Err(Error::Conflict { height });
            }
        } else {
            let archive = self.archive.take().expect("archive unavailable");
            self.archive = Some(
                archive
                    .put(height.get(), digest, digest)
                    .await?
                    .sync()
                    .await?,
            );
        }

        if let Some(waiters) = self.waiters.remove(&height) {
            self.pending_requests -= waiters.len();
            for waiter in waiters {
                Self::resolve(waiter, digest);
            }
        }
        acknowledgement.acknowledge();
        Ok(())
    }

    fn resolve(request: Request<B::Checkpoint>, digest: B::Checkpoint) {
        match request {
            Request::Propose(response) => {
                let _ = response.send(digest);
            }
            Request::Verify(candidate, response) => {
                let _ = response.send(candidate == digest);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::tests::mocks::MockBlock;
    use commonware_consensus::Heightable as _;
    use commonware_cryptography::{
        Digestible as _, Hasher as _, Sha256, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, acknowledgement::Exact};

    type TestBlock = MockBlock<Sha256Digest, u64>;

    impl FinalizedBlock for TestBlock {
        type Checkpoint = Sha256Digest;

        fn finalized_checkpoint(&self) -> (Height, Self::Checkpoint) {
            (self.height(), self.digest())
        }
    }

    fn block(height: u64, timestamp: u64) -> TestBlock {
        MockBlock::new::<Sha256>(
            timestamp,
            Sha256::hash(&[b"parent"]),
            Height::new(height),
            timestamp,
        )
    }

    fn config(context: &deterministic::Context) -> Config<()> {
        Config {
            archive: immutable::Config {
                metadata_partition: "checkpoint_metadata".into(),
                freezer_table_partition: "checkpoint_table".into(),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 32,
                freezer_key_partition: "checkpoint_keys".into(),
                freezer_key_page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
                freezer_value_partition: "checkpoint_values".into(),
                freezer_value_target_size: 1024 * 1024,
                freezer_value_compression: None,
                ordinal_partition: "checkpoint_ordinal".into(),
                items_per_section: NZU64!(64),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config: (),
            },
            mailbox_size: NZUsize!(1),
            max_pending_requests: NZUsize!(8),
        }
    }

    #[test]
    fn recovery_and_report_propose_race() {
        deterministic::Runner::default().start(|context| async move {
            let finalized = block(7, 1);
            let expected = finalized.digest();
            let (actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("first"), config(&context))
                    .await
                    .unwrap();
            let handle = actor.start();

            let proposal = handler.propose(Height::new(7)).await;
            let verification = handler.verify(Height::new(7), expected).await;
            let (acknowledgement, acknowledged) = Exact::handle();
            assert!(
                handler
                    .report(Update::Block(Arc::new(finalized), acknowledgement))
                    .accepted()
            );
            assert_eq!(proposal.await.unwrap(), expected);
            assert!(verification.await.unwrap());
            acknowledged.await.unwrap();

            handle.abort();
            let (recovered, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("second"), config(&context))
                    .await
                    .unwrap();
            let recovered_handle = recovered.start();
            assert_eq!(
                handler.propose(Height::new(7)).await.await.unwrap(),
                expected
            );
            recovered_handle.abort();
        });
    }

    #[test]
    fn conflicting_finalization_is_fatal_and_unacknowledged() {
        deterministic::Runner::default().start(|context| async move {
            let (actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("actor"), config(&context))
                    .await
                    .unwrap();
            let handle = actor.start();

            let (first_ack, first_waiter) = Exact::handle();
            let _ = handler.report(Update::Block(Arc::new(block(3, 1)), first_ack));
            first_waiter.await.unwrap();

            let (conflict_ack, conflict_waiter) = Exact::handle();
            let _ = handler.report(Update::Block(Arc::new(block(3, 2)), conflict_ack));
            assert!(matches!(
                handle.await,
                Ok(Err(Error::Conflict {
                    height
                })) if height == Height::new(3)
            ));
            assert!(conflict_waiter.await.is_err());
        });
    }

    #[test]
    fn pending_requests_are_bounded() {
        deterministic::Runner::default().start(|context| async move {
            let mut cfg = config(&context);
            cfg.max_pending_requests = NZUsize!(1);
            let (actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("actor"), cfg)
                    .await
                    .unwrap();

            let first = handler.propose(Height::new(1)).await;
            let second = handler.propose(Height::new(2)).await;
            let third = handler.propose(Height::new(3)).await;
            let handle = actor.start();
            let (acknowledgement, acknowledged) = Exact::handle();
            let _ = handler.report(Update::Block(Arc::new(block(1, 1)), acknowledgement));

            assert!(first.await.is_ok());
            assert!(second.await.is_err());
            assert!(third.await.is_err());
            acknowledged.await.unwrap();
            handle.abort();
        });
    }
}
