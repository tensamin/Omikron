use std::{future::Future, sync::Mutex, time::Duration};
use tokio::{sync::watch, task::JoinSet};

use super::connection::MtpReceiver;

/// Process-owned handles survive connection teardown. Completed operations are
/// reaped on the next submission; pending external mutations are never aborted.
static OPERATIONS: std::sync::LazyLock<Mutex<JoinSet<()>>> =
    std::sync::LazyLock::new(|| Mutex::new(JoinSet::new()));
static COMPLETED_GROUPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static OPERATION_FAILURES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(crate) fn record_failure(error: tokio::task::JoinError) {
    OPERATION_FAILURES.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    crate::log_err!(
        0,
        crate::util::logger::PrintType::General,
        "Supervised operation failed: {}",
        error
    );
}

/// Bounded observation never removes unfinished handles from process ownership.
/// The listener must stop admitting connections before its caller uses this.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OperationDrainReport {
    /// Supervisor ownership groups completed since process start.
    pub(crate) completed: usize,
    /// Pending ownership groups, including connection handlers, not task count.
    pub(crate) remaining: usize,
    pub(crate) failures: usize,
    pub(crate) deadline_reached: bool,
    pub(crate) uncertain_remote: Result<usize, String>,
    pub(crate) pending_local_publications: Result<usize, String>,
}

impl OperationDrainReport {
    pub(crate) fn is_complete(&self) -> bool {
        self.remaining == 0
            && self.failures == 0
            && !self.deadline_reached
            && self.uncertain_remote == Ok(0)
            && self.pending_local_publications == Ok(0)
    }
}

pub(crate) async fn drain_process_operations(budget: Duration) -> OperationDrainReport {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let remaining = {
            let mut operations = OPERATIONS.lock().expect("operation supervisor poisoned");
            while let Some(result) = operations.try_join_next() {
                match result {
                    Ok(()) => {
                        COMPLETED_GROUPS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                    }
                    Err(error) => record_failure(error),
                }
            }
            operations.len()
        };
        if remaining == 0 || tokio::time::Instant::now() >= deadline {
            let recovery = crate::omega::mutation_recovery_report();
            return OperationDrainReport {
                completed: COMPLETED_GROUPS.load(std::sync::atomic::Ordering::Acquire),
                remaining,
                failures: OPERATION_FAILURES.load(std::sync::atomic::Ordering::Acquire),
                deadline_reached: tokio::time::Instant::now() >= deadline,
                uncertain_remote: recovery.clone().map(|(remote, _)| remote),
                pending_local_publications: recovery.map(|(_, local)| local),
            };
        }
        tokio::time::sleep_until(
            deadline.min(tokio::time::Instant::now() + Duration::from_millis(10)),
        )
        .await;
    }
}

/// Deadline expiry reports incomplete work, but does not authorize dropping the
/// runtime. Only durable uncertain outcomes may remain when this returns.
pub(crate) async fn finish_process_operations() -> OperationDrainReport {
    loop {
        let report = drain_process_operations(Duration::from_secs(30)).await;
        if report.remaining == 0 {
            return report;
        }
        crate::log_err!(
            0,
            crate::util::logger::PrintType::General,
            "Still waiting for admitted operations after shutdown deadline: {report:?}"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskSubmissionError {
    Draining,
    Closed,
}

impl std::fmt::Display for TaskSubmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Draining => "connection tasks are draining",
            Self::Closed => "connection tasks are closed",
        })
    }
}

impl std::error::Error for TaskSubmissionError {}

pub(crate) fn supervise(mut tasks: JoinSet<()>) -> tokio::sync::oneshot::Receiver<()> {
    let (completed, completion) = tokio::sync::oneshot::channel();
    let mut operations = OPERATIONS.lock().expect("operation supervisor poisoned");
    while let Some(result) = operations.try_join_next() {
        match result {
            Ok(()) => {
                COMPLETED_GROUPS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }
            Err(error) => record_failure(error),
        }
    }
    operations.spawn(async move {
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                record_failure(error);
            }
        }
        let _ = completed.send(());
    });
    completion
}

impl Drop for MessageTasks {
    fn drop(&mut self) {
        if let Some(tasks) = self
            .tasks
            .get_mut()
            .expect("message task lock poisoned")
            .take()
            && !tasks.is_empty()
        {
            // Unexpected connection-owner cancellation must also retain mutations.
            drop(supervise(tasks));
        }
    }
}

pub(crate) struct MessageTasks {
    message_drain: Duration,
    tasks: Mutex<Option<JoinSet<()>>>,
    cancellable: Mutex<Option<JoinSet<()>>>,
    draining: watch::Sender<bool>,
    shutdown: watch::Receiver<bool>,
    #[cfg(test)]
    pub(crate) drain_expired: tokio::sync::Notify,
}

impl MessageTasks {
    pub(crate) fn new(shutdown: watch::Receiver<bool>, message_drain: Duration) -> Self {
        Self {
            message_drain,
            tasks: Mutex::new(Some(JoinSet::new())),
            cancellable: Mutex::new(Some(JoinSet::new())),
            draining: watch::channel(false).0,
            shutdown,
            #[cfg(test)]
            drain_expired: tokio::sync::Notify::new(),
        }
    }

    /// Operations must acquire async locks before synchronous persistence and
    /// publication. Cancellation may drop preparation or post-commit delivery,
    /// but must not split a durable mutation from its local state update.
    pub(crate) fn spawn(
        &self,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), TaskSubmissionError> {
        let mut tasks = self.tasks.lock().expect("message task lock poisoned");
        if *self.draining.borrow() {
            return Err(if tasks.is_some() {
                TaskSubmissionError::Draining
            } else {
                TaskSubmissionError::Closed
            });
        }
        if let Some(tasks) = tasks.as_mut() {
            while let Some(result) = tasks.try_join_next() {
                if let Err(error) = result {
                    record_failure(error);
                }
            }
            tasks.spawn(task);
            Ok(())
        } else {
            Err(TaskSubmissionError::Closed)
        }
    }

    /// Read-only or best-effort work has no connection-local rollback requirement.
    pub(crate) fn spawn_cancellable(
        &self,
        task: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), TaskSubmissionError> {
        let mut draining = self.draining.subscribe();
        let mut tasks = self.cancellable.lock().expect("message task lock poisoned");
        let Some(tasks) = tasks.as_mut() else {
            return Err(TaskSubmissionError::Closed);
        };
        if *draining.borrow() {
            return Err(TaskSubmissionError::Draining);
        }
        while let Some(result) = tasks.try_join_next() {
            if let Err(error) = result {
                record_failure(error);
            }
        }
        tasks.spawn(async move {
            tokio::select! {
                _ = draining.wait_for(|stop| *stop) => {},
                _ = task => {},
            }
        });
        Ok(())
    }

    /// Drops preparation or read-only work on disconnect. Mutation-bearing work
    /// must instead complete its transaction or provide cancellation rollback.
    pub(crate) async fn while_connected<T>(
        &self,
        receiver: &MtpReceiver,
        operation: impl Future<Output = T>,
    ) -> Option<T> {
        let mut shutdown = self.shutdown.clone();
        let mut poll = tokio::time::interval(Duration::from_millis(50));
        tokio::pin!(operation);
        loop {
            tokio::select! {
                biased;
                _ = shutdown.wait_for(|stop| *stop) => return None,
                _ = poll.tick() => {
                    if receiver.close_reason().is_some() { return None; }
                },
                result = &mut operation => return Some(result),
            }
        }
    }

    pub(crate) async fn drain(&self) {
        // Serialize the transition with both submission paths.
        {
            let _tasks = self.tasks.lock().expect("message task lock poisoned");
            let _cancellable = self.cancellable.lock().expect("message task lock poisoned");
            self.draining.send_replace(true);
        }
        let cancellable = self
            .cancellable
            .lock()
            .expect("message task lock poisoned")
            .take();
        if let Some(mut cancellable) = cancellable {
            cancellable.abort_all();
            while let Some(result) = cancellable.join_next().await {
                if let Err(error) = result
                    && !error.is_cancelled()
                {
                    record_failure(error);
                }
            }
        }
        // Release the synchronous lock before waiting. Child tasks cannot publish
        // new work once the set has been taken.
        let tasks = self
            .tasks
            .lock()
            .expect("message task lock poisoned")
            .take();
        let Some(tasks) = tasks else {
            return;
        };
        let remaining = tasks.len();
        // Transfer before the first await so cancelling drain cannot abort work.
        let completion = supervise(tasks);
        if tokio::time::timeout(self.message_drain, completion)
            .await
            .is_err()
        {
            #[cfg(test)]
            self.drain_expired.notify_one();
            crate::log_err!(
                0,
                crate::util::logger::PrintType::General,
                "Incomplete message drain: remaining={} budget={:?}; transferring mutations to process supervision",
                remaining,
                self.message_drain
            );
        }
    }
}

pub(crate) async fn finish_cleanup(timeout: Duration, cleanup: impl Future<Output = ()>) {
    if tokio::time::timeout(timeout, cleanup).await.is_err() {
        crate::log_err!(
            0,
            crate::util::logger::PrintType::General,
            "Connection cleanup exceeded its {} second budget",
            timeout.as_secs()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_runtime_exit_preserves_a_stalled_remote_mutation_intent() {
        let path =
            std::env::temp_dir().join(format!("shutdown-intent-{}.sqlite3", uuid::Uuid::new_v4()));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let request = br#"{"service":"livekit","operation":"delete_room","call_id":"stable-call"}"#;
        runtime.block_on(async {
            let mut tasks = JoinSet::new();
            let (started, receive) = tokio::sync::oneshot::channel();
            let path = path.clone();
            tasks.spawn(async move {
                let journal = crate::omega::MutationJournal::open(&path).unwrap();
                let _operation_id = journal.begin_record(request).unwrap();
                started.send(()).unwrap();
                // A remote mutation may already have started and never reply.
                std::future::pending::<()>().await;
            });
            drop(supervise(tasks));
            receive.await.unwrap();
            let report = drain_process_operations(Duration::from_millis(5)).await;
            assert!(report.remaining > 0);
            assert!(report.deadline_reached);
            assert!(!report.is_complete());
        });
        let stopped = std::time::Instant::now();
        runtime.shutdown_timeout(Duration::from_millis(100));
        assert!(stopped.elapsed() < Duration::from_secs(1));
        let journal = crate::omega::MutationJournal::open(&path).unwrap();
        assert_eq!(journal.unresolved().unwrap(), 1);
        assert!(
            journal
                .begin_record(request)
                .unwrap_err()
                .contains("uncertain outcome")
        );
        drop(journal);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn submissions_reject_draining_and_closed() {
        let (_shutdown, receiver) = watch::channel(false);
        let tasks = MessageTasks::new(receiver, Duration::from_millis(1));
        tasks.draining.send_replace(true);
        assert_eq!(tasks.spawn(async {}), Err(TaskSubmissionError::Draining));
        assert_eq!(
            tasks.spawn_cancellable(async {}),
            Err(TaskSubmissionError::Draining)
        );
        tasks.drain().await;
        assert_eq!(tasks.spawn(async {}), Err(TaskSubmissionError::Closed));
        assert_eq!(
            tasks.spawn_cancellable(async {}),
            Err(TaskSubmissionError::Closed)
        );
    }

    #[tokio::test]
    async fn process_owner_retains_mutation_after_finite_drain_and_connection_drop() {
        let (_shutdown, receiver) = watch::channel(false);
        let tasks = MessageTasks::new(receiver, Duration::from_millis(1));
        let (release, wait) = tokio::sync::oneshot::channel();
        let (completed, completion) = tokio::sync::oneshot::channel();
        tasks
            .spawn(async move {
                wait.await.unwrap();
                completed.send(()).unwrap();
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), tasks.drain())
            .await
            .unwrap();
        drop(tasks);
        let report = tokio::time::timeout(
            Duration::from_secs(1),
            drain_process_operations(Duration::from_millis(1)),
        )
        .await
        .unwrap();
        assert!(report.remaining > 0);
        assert!(report.deadline_reached);
        assert!(!report.is_complete());
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), completion)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn process_drain_reports_completed_groups_and_panics() {
        let completed_before = COMPLETED_GROUPS.load(std::sync::atomic::Ordering::Acquire);
        let failures_before = OPERATION_FAILURES.load(std::sync::atomic::Ordering::Acquire);
        let mut operations = JoinSet::new();
        operations.spawn(async { panic!("mutation panic must reach the shutdown report") });
        supervise(operations).await.unwrap();
        let report = drain_process_operations(Duration::from_secs(1)).await;
        assert!(report.completed > completed_before);
        assert!(report.failures > failures_before);
        assert!(!report.is_complete());
    }
}
