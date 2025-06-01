use std::sync::{Arc, Mutex, Condvar};
use std::thread;
use std::collections::VecDeque;
use std::time::Duration;

const NUM_CORES: usize = 14;
const WORKER_THREADS: usize = NUM_CORES - 1; // Réserver un cœur pour le système
const TASK_QUEUE_SIZE: usize = 1000;

pub struct ThreadPool {
    workers: Vec<Worker>,
    task_queue: Arc<(Mutex<VecDeque<Task>>, Condvar)>,
    running: Arc<Mutex<bool>>,
}

struct Worker {
    thread: Option<thread::JoinHandle<()>>,
}

struct Task {
    function: Box<dyn FnOnce() + Send>,
    priority: u8,
}

impl ThreadPool {
    pub fn new() -> Self {
        let task_queue = Arc::new((Mutex::new(VecDeque::with_capacity(TASK_QUEUE_SIZE)), Condvar::new()));
        let running = Arc::new(Mutex::new(true));
        let mut workers = Vec::with_capacity(WORKER_THREADS);

        for id in 0..WORKER_THREADS {
            let task_queue = Arc::clone(&task_queue);
            let running = Arc::clone(&running);

            let worker = Worker {
                thread: Some(thread::spawn(move || {
                    Self::worker_loop(id, task_queue, running);
                })),
            };

            workers.push(worker);
        }

        Self {
            workers,
            task_queue,
            running,
        }
    }

    fn worker_loop(
        id: usize,
        task_queue: Arc<(Mutex<VecDeque<Task>>, Condvar)>,
        running: Arc<Mutex<bool>>,
    ) {
        let (queue, cvar) = &*task_queue;

        while *running.lock().unwrap() {
            let task = {
                let mut queue = queue.lock().unwrap();
                while queue.is_empty() && *running.lock().unwrap() {
                    queue = cvar.wait(queue).unwrap();
                }

                if !*running.lock().unwrap() {
                    break;
                }

                queue.pop_front()
            };

            if let Some(task) = task {
                (task.function)();
            }
        }
    }

    pub fn execute<F>(&self, f: F, priority: u8)
    where
        F: FnOnce() + Send + 'static,
    {
        let task = Task {
            function: Box::new(f),
            priority,
        };

        let (queue, cvar) = &*self.task_queue;
        let mut queue = queue.lock().unwrap();

        // Insérer la tâche en fonction de sa priorité
        let position = queue
            .iter()
            .position(|t| t.priority < priority)
            .unwrap_or(queue.len());
        queue.insert(position, task);

        cvar.notify_one();
    }

    pub fn shutdown(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
        drop(running);

        let (_, cvar) = &*self.task_queue;
        cvar.notify_all();

        for worker in &self.workers {
            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn test_thread_pool_execution() {
        let pool = ThreadPool::new();
        let counter = Arc::new(AtomicUsize::new(0));

        for i in 0..100 {
            let counter = Arc::clone(&counter);
            pool.execute(
                move || {
                    counter.fetch_add(1, Ordering::SeqCst);
                },
                (i % 3) as u8,
            );
        }

        thread::sleep(Duration::from_millis(100));
        assert_eq!(counter.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn test_priority_execution() {
        let pool = ThreadPool::new();
        let execution_order = Arc::new(Mutex::new(Vec::new()));

        for i in 0..5 {
            let execution_order = Arc::clone(&execution_order);
            pool.execute(
                move || {
                    execution_order.lock().unwrap().push(i);
                },
                i as u8,
            );
        }

        thread::sleep(Duration::from_millis(100));
        let order = execution_order.lock().unwrap();
        assert_eq!(order.len(), 5);
        assert!(order.windows(2).all(|w| w[0] <= w[1]));
    }
} 