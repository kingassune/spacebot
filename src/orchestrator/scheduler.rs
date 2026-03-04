//! Priority-based task scheduler for security operations.
//!
//! Queues and dispatches security tasks according to priority, resource
//! availability, and dependency constraints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BinaryHeap;
use std::cmp::Ordering;

/// Priority level for a scheduled task (higher value = higher priority).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskPriority {
    Low = 1,
    Normal = 5,
    High = 8,
    Critical = 10,
}

impl TaskPriority {
    /// Numeric priority value.
    pub fn value(self) -> u8 {
        self as u8
    }
}

/// State of a scheduled task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaskState {
    /// Waiting in the queue.
    Queued,
    /// Currently executing.
    Running,
    /// Completed successfully.
    Done,
    /// Failed during execution.
    Failed(String),
    /// Cancelled before execution.
    Cancelled,
}

/// A task in the scheduler queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTask {
    /// Unique task identifier.
    pub id: String,
    /// Human-readable task name.
    pub name: String,
    /// Priority.
    pub priority: TaskPriority,
    /// Current state.
    pub state: TaskState,
    /// Optional earliest start time.
    pub not_before: Option<DateTime<Utc>>,
    /// Task IDs that must complete before this task can start.
    pub depends_on: Vec<String>,
    /// Estimated execution duration in seconds.
    pub estimated_duration_secs: u64,
    /// Timestamp when the task was queued.
    pub queued_at: DateTime<Utc>,
    /// Timestamp when execution started.
    pub started_at: Option<DateTime<Utc>>,
    /// Timestamp when execution completed.
    pub completed_at: Option<DateTime<Utc>>,
}

impl ScheduledTask {
    /// Create a new task with the given name and priority.
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        priority: TaskPriority,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            priority,
            state: TaskState::Queued,
            not_before: None,
            depends_on: Vec::new(),
            estimated_duration_secs: 300,
            queued_at: Utc::now(),
            started_at: None,
            completed_at: None,
        }
    }
}

/// Wrapper to allow `ScheduledTask` to be sorted in a max-heap by priority.
#[derive(Debug)]
struct PriorityEntry {
    priority: u8,
    task_id: String,
}

impl PartialEq for PriorityEntry {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority
    }
}

impl Eq for PriorityEntry {}

impl PartialOrd for PriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority.cmp(&other.priority)
    }
}

/// Result of executing a scheduled task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    /// Task that was executed.
    pub task_id: String,
    /// Task name.
    pub task_name: String,
    /// Whether execution succeeded.
    pub success: bool,
    /// Output message.
    pub output: String,
    /// Actual execution duration in seconds.
    pub duration_secs: u64,
}

/// Priority-based task scheduler.
pub struct TaskScheduler {
    /// All tasks known to the scheduler (by ID).
    tasks: std::collections::HashMap<String, ScheduledTask>,
    /// Priority queue of task IDs awaiting execution.
    queue: BinaryHeap<PriorityEntry>,
    /// Completed task results.
    results: Vec<TaskResult>,
}

impl TaskScheduler {
    /// Create a new empty scheduler.
    pub fn new() -> Self {
        Self {
            tasks: std::collections::HashMap::new(),
            queue: BinaryHeap::new(),
            results: Vec::new(),
        }
    }

    /// Schedule a new task.
    pub fn schedule(&mut self, task: ScheduledTask) {
        let entry = PriorityEntry {
            priority: task.priority.value(),
            task_id: task.id.clone(),
        };
        self.tasks.insert(task.id.clone(), task);
        self.queue.push(entry);
    }

    /// Dequeue and return the highest-priority ready task.
    ///
    /// A task is "ready" when all its dependencies have completed and its
    /// `not_before` constraint is satisfied.
    pub fn next_ready_task(&mut self) -> Option<ScheduledTask> {
        let now = Utc::now();
        let mut deferred = Vec::new();

        while let Some(entry) = self.queue.pop() {
            let task = match self.tasks.get_mut(&entry.task_id) {
                Some(t) => t,
                None => continue,
            };

            // Skip if not yet within the allowed window.
            if let Some(not_before) = task.not_before {
                if now < not_before {
                    deferred.push(entry);
                    continue;
                }
            }

            // Skip if dependencies are not yet done.
            let deps_satisfied = task.depends_on.iter().all(|dep_id| {
                self.results.iter().any(|r| &r.task_id == dep_id && r.success)
            });
            if !deps_satisfied {
                deferred.push(entry);
                continue;
            }

            // Re-queue deferred tasks.
            for d in deferred {
                self.queue.push(d);
            }

            task.state = TaskState::Running;
            task.started_at = Some(Utc::now());
            return Some(task.clone());
        }

        // Re-queue all deferred tasks.
        for d in deferred {
            self.queue.push(d);
        }
        None
    }

    /// Mark a task as completed and store its result.
    pub fn complete_task(&mut self, task_id: &str, success: bool, output: String) {
        if let Some(task) = self.tasks.get_mut(task_id) {
            task.state = if success {
                TaskState::Done
            } else {
                TaskState::Failed(output.clone())
            };
            task.completed_at = Some(Utc::now());
            let duration = task
                .started_at
                .map(|s| (Utc::now() - s).num_seconds().max(0) as u64)
                .unwrap_or(0);

            self.results.push(TaskResult {
                task_id: task_id.to_string(),
                task_name: task.name.clone(),
                success,
                output,
                duration_secs: duration,
            });
        }
    }

    /// Cancel a queued task.
    pub fn cancel_task(&mut self, task_id: &str) {
        if let Some(task) = self.tasks.get_mut(task_id) {
            if task.state == TaskState::Queued {
                task.state = TaskState::Cancelled;
            }
        }
    }

    /// Return all completed task results.
    pub fn results(&self) -> &[TaskResult] {
        &self.results
    }

    /// Return number of tasks still queued.
    pub fn queued_count(&self) -> usize {
        self.tasks
            .values()
            .filter(|t| t.state == TaskState::Queued)
            .count()
    }

    /// Return number of tasks currently running.
    pub fn running_count(&self) -> usize {
        self.tasks
            .values()
            .filter(|t| t.state == TaskState::Running)
            .count()
    }
}

impl Default for TaskScheduler {
    fn default() -> Self {
        Self::new()
    }
}
