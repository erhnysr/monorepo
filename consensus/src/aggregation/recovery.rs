//! Shared scheduling for active aggregation recovery.

use super::types::RecoveryKey;
use commonware_actor::{Feedback, mailbox};
use commonware_macros::select_loop;
use commonware_resolver::Resolver;
use commonware_runtime::{ContextCell, Handle, Metrics, Spawner, spawn_cell};
use std::{
    collections::{BTreeSet, VecDeque},
    num::NonZeroUsize,
    marker::PhantomData,
};

/// Requests and cancels aggregation certificate recovery.
///
/// Implementations schedule logical recovery only. Recovered certificates must be delivered to
/// the matching [`super::Mailbox`] so the engine applies its authenticated epoch, range, and
/// signature checks.
pub trait Recoverer: Clone + Send + 'static {
    /// Requests `key` if it is not already requested.
    fn fetch(&mut self, key: RecoveryKey) -> Feedback;

    /// Cancels the exact requested or queued `key`.
    fn cancel(&mut self, key: RecoveryKey) -> Feedback;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregation::types::RecoveryNamespace,
        types::{Epoch, Height},
    };
    use commonware_resolver::Fetch;
    use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, sync::Mutex};
    use std::sync::Arc;

    #[derive(Clone, Default)]
    struct MockResolver {
        state: Arc<Mutex<ResolverState>>,
    }

    #[derive(Default)]
    struct ResolverState {
        active: BTreeSet<RecoveryKey>,
        events: Vec<(bool, RecoveryKey)>,
        high_water: usize,
    }

    impl Resolver for MockResolver {
        type Key = RecoveryKey;
        type Subscriber = ();

        fn fetch<F>(&mut self, fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            let key = fetch.into().key;
            let mut state = self.state.lock();
            state.active.insert(key);
            state.events.push((true, key));
            state.high_water = state.high_water.max(state.active.len());
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            for fetch in fetches {
                self.fetch(fetch);
            }
            Feedback::Ok
        }

        fn retain(
            &mut self,
            predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            let mut state = self.state.lock();
            let removed: Vec<_> = state
                .active
                .iter()
                .copied()
                .filter(|key| !predicate(key, &()))
                .collect();
            for key in removed {
                state.active.remove(&key);
                state.events.push((false, key));
            }
            Feedback::Ok
        }
    }

    fn key(epoch: u64, position: u64) -> RecoveryKey {
        RecoveryKey {
            namespace: RecoveryNamespace::derive(b"coordinator-test"),
            epoch: Epoch::new(epoch),
            position: Height::new(position),
        }
    }

    #[test]
    fn cap_dedup_exact_cancel_and_fifo_across_scopes() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (mut coordinator, _) = RecoveryCoordinator::new(
                context,
                resolver,
                NZUsize!(2),
                NZUsize!(16),
            );
            let keys = [key(1, 0), key(2, 0), key(1, 1), key(2, 1)];

            coordinator.fetch(keys[0]);
            coordinator.fetch(keys[1]);
            coordinator.fetch(keys[2]);
            coordinator.fetch(keys[3]);
            coordinator.fetch(keys[2]);
            coordinator.cancel(keys[3]);
            coordinator.cancel(keys[0]);
            coordinator.cancel(keys[1]);

            let state = state.lock();
            assert_eq!(state.high_water, 2);
            assert_eq!(
                state.events,
                vec![
                    (true, keys[0]),
                    (true, keys[1]),
                    (false, keys[0]),
                    (true, keys[2]),
                    (false, keys[1]),
                ]
            );
            assert_eq!(state.active, BTreeSet::from([keys[2]]));
        });
    }

    #[test]
    fn runtime_shutdown_cancels_active_requests_with_live_handle() {
        deterministic::Runner::default().start(|context| async move {
            let resolver = MockResolver::default();
            let state = resolver.state.clone();
            let (coordinator, mut recovery) = RecoveryCoordinator::new(
                context.child("coordinator"),
                resolver,
                NZUsize!(1),
                NZUsize!(4),
            );
            let handle = coordinator.start();
            let requested = key(1, 0);
            assert!(recovery.fetch(requested).accepted());
            while state.lock().active.is_empty() {
                context.sleep(std::time::Duration::from_millis(1)).await;
            }

            context.child("stop").stop(0, None).await.unwrap();
            handle.await.expect("recovery coordinator failed");

            let state = state.lock();
            assert!(state.active.is_empty());
            assert_eq!(state.events, vec![(true, requested), (false, requested)]);
            drop(recovery);
        });
    }
}

#[derive(Clone, Copy)]
enum Message {
    Fetch(RecoveryKey),
    Cancel(RecoveryKey),
}

impl mailbox::Policy for Message {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

/// Cloneable handle to a node-wide aggregation recovery coordinator.
pub struct Recovery<R> {
    mailbox: mailbox::Sender<Message>,
    _resolver: PhantomData<fn() -> R>,
}

impl<R> Clone for Recovery<R> {
    fn clone(&self) -> Self {
        Self {
            mailbox: self.mailbox.clone(),
            _resolver: PhantomData,
        }
    }
}

impl<R: Send + 'static> Recoverer for Recovery<R> {
    fn fetch(&mut self, key: RecoveryKey) -> Feedback {
        self.mailbox.enqueue(Message::Fetch(key))
    }

    fn cancel(&mut self, key: RecoveryKey) -> Feedback {
        self.mailbox.enqueue(Message::Cancel(key))
    }
}

/// Actor that shares one logical outstanding recovery cap across engine scopes.
///
/// Requests beyond the cap are deduplicated and queued in FIFO order. Canceling an active key
/// sends the resolver retain operation before issuing the next queued fetch, so a released slot
/// cannot transiently represent two logical requests in resolver mailbox order.
pub struct RecoveryCoordinator<E, R>
where
    E: Spawner + Metrics,
    R: Resolver<Key = RecoveryKey, Subscriber = ()>,
{
    context: ContextCell<E>,
    resolver: R,
    receiver: mailbox::Receiver<Message>,
    cap: usize,
    active: BTreeSet<RecoveryKey>,
    queued: VecDeque<RecoveryKey>,
    queued_set: BTreeSet<RecoveryKey>,
}

impl<E, R> RecoveryCoordinator<E, R>
where
    E: Spawner + Metrics,
    R: Resolver<Key = RecoveryKey, Subscriber = ()>,
{
    /// Creates a coordinator and its cloneable handle.
    pub fn new(
        context: E,
        resolver: R,
        outstanding: NonZeroUsize,
        mailbox_size: NonZeroUsize,
    ) -> (Self, Recovery<R>) {
        let (mailbox, receiver) = mailbox::new(context.child("mailbox"), mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                resolver,
                receiver,
                cap: outstanding.get(),
                active: BTreeSet::new(),
                queued: VecDeque::new(),
                queued_set: BTreeSet::new(),
            },
            Recovery {
                mailbox,
                _resolver: PhantomData,
            },
        )
    }

    /// Starts the coordinator actor.
    pub fn start(self) -> Handle<()> {
        let mut this = self;
        spawn_cell!(this.context, this.run())
    }

    async fn run(mut self) {
        select_loop! {
            self.context,
            on_stopped => {},
            Some(message) = self.receiver.recv() else break => match message {
                Message::Fetch(key) => self.fetch(key),
                Message::Cancel(key) => self.cancel(key),
            },
        }
        self.cancel_active();
    }

    fn fetch(&mut self, key: RecoveryKey) {
        if self.active.contains(&key) || self.queued_set.contains(&key) {
            return;
        }
        if self.active.len() < self.cap {
            if self.resolver.fetch(key).accepted() {
                self.active.insert(key);
            }
            return;
        }
        self.queued.push_back(key);
        self.queued_set.insert(key);
    }

    fn cancel(&mut self, key: RecoveryKey) {
        if self.queued_set.remove(&key) {
            self.queued.retain(|queued| *queued != key);
            return;
        }
        if !self.active.remove(&key) {
            return;
        }
        self.resolver.retain(move |candidate, ()| *candidate != key);
        self.fill();
    }

    fn fill(&mut self) {
        while self.active.len() < self.cap {
            let Some(key) = self.queued.pop_front() else {
                break;
            };
            self.queued_set.remove(&key);
            if self.resolver.fetch(key).accepted() {
                self.active.insert(key);
            }
        }
    }

    fn cancel_active(&mut self) {
        if self.active.is_empty() {
            return;
        }
        let active = std::mem::take(&mut self.active);
        self.resolver
            .retain(move |key, ()| !active.contains(key));
    }
}
