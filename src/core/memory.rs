use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const MAX_MEMORY: usize = 32 * 1024 * 1024 * 1024; // 32 GB
const MEMORY_POOL_SIZE: usize = 1024 * 1024 * 1024; // 1 GB par pool
const NUM_POOLS: usize = MAX_MEMORY / MEMORY_POOL_SIZE;

pub struct MemoryManager {
    total_allocated: AtomicUsize,
    pools: Vec<Mutex<MemoryPool>>,
    allocation_times: Mutex<HashMap<*const u8, Instant>>,
}

struct MemoryPool {
    memory: Vec<u8>,
    used: Vec<bool>,
    last_cleanup: Instant,
}

impl MemoryManager {
    pub fn new() -> Self {
        let mut pools = Vec::with_capacity(NUM_POOLS);
        for _ in 0..NUM_POOLS {
            pools.push(Mutex::new(MemoryPool {
                memory: vec![0; MEMORY_POOL_SIZE],
                used: vec![false; MEMORY_POOL_SIZE],
                last_cleanup: Instant::now(),
            }));
        }

        Self {
            total_allocated: AtomicUsize::new(0),
            pools,
            allocation_times: Mutex::new(HashMap::new()),
        }
    }

    pub fn allocate(&self, size: usize) -> Option<*mut u8> {
        if size > MEMORY_POOL_SIZE {
            return None;
        }

        let total = self.total_allocated.fetch_add(size, Ordering::SeqCst);
        if total + size > MAX_MEMORY {
            self.total_allocated.fetch_sub(size, Ordering::SeqCst);
            return None;
        }

        for pool in &self.pools {
            if let Ok(mut pool) = pool.lock() {
                if let Some(offset) = self.find_free_space(&pool.used, size) {
                    pool.used[offset..offset + size].fill(true);
                    let ptr = &mut pool.memory[offset] as *mut u8;
                    
                    // Enregistrer le temps d'allocation
                    if let Ok(mut times) = self.allocation_times.lock() {
                        times.insert(ptr, Instant::now());
                    }
                    
                    return Some(ptr);
                }
            }
        }

        None
    }

    pub fn deallocate(&self, ptr: *mut u8, size: usize) {
        for pool in &self.pools {
            if let Ok(mut pool) = pool.lock() {
                let pool_start = pool.memory.as_ptr() as usize;
                let pool_end = pool_start + MEMORY_POOL_SIZE;
                let ptr_addr = ptr as usize;

                if ptr_addr >= pool_start && ptr_addr < pool_end {
                    let offset = ptr_addr - pool_start;
                    pool.used[offset..offset + size].fill(false);
                    self.total_allocated.fetch_sub(size, Ordering::SeqCst);
                    
                    // Supprimer l'enregistrement du temps d'allocation
                    if let Ok(mut times) = self.allocation_times.lock() {
                        times.remove(&ptr);
                    }
                    
                    break;
                }
            }
        }
    }

    fn find_free_space(&self, used: &[bool], size: usize) -> Option<usize> {
        let mut current_run = 0;
        for (i, &is_used) in used.iter().enumerate() {
            if !is_used {
                current_run += 1;
                if current_run >= size {
                    return Some(i - size + 1);
                }
            } else {
                current_run = 0;
            }
        }
        None
    }

    pub fn cleanup_old_allocations(&self, max_age: Duration) {
        if let Ok(times) = self.allocation_times.lock() {
            let now = Instant::now();
            let old_allocations: Vec<*const u8> = times
                .iter()
                .filter(|(_, &time)| now.duration_since(time) > max_age)
                .map(|(&ptr, _)| ptr)
                .collect();

            for ptr in old_allocations {
                // Déterminer la taille de l'allocation (à implémenter selon votre logique)
                let size = 1024; // Exemple
                self.deallocate(ptr as *mut u8, size);
            }
        }
    }

    pub fn get_memory_usage(&self) -> f64 {
        let total = self.total_allocated.load(Ordering::SeqCst);
        (total as f64 / MAX_MEMORY as f64) * 100.0
    }
}

unsafe impl GlobalAlloc for MemoryManager {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Some(ptr) = self.allocate(layout.size()) {
            ptr
        } else {
            System.alloc(layout)
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.deallocate(ptr, layout.size());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_allocation() {
        let manager = MemoryManager::new();
        let size = 1024;
        
        if let Some(ptr) = manager.allocate(size) {
            assert!(!ptr.is_null());
            manager.deallocate(ptr, size);
        } else {
            panic!("Échec de l'allocation");
        }
    }

    #[test]
    fn test_memory_usage() {
        let manager = MemoryManager::new();
        let size = 1024 * 1024; // 1 MB
        
        for _ in 0..10 {
            if let Some(ptr) = manager.allocate(size) {
                manager.deallocate(ptr, size);
            }
        }
        
        assert!(manager.get_memory_usage() < 1.0);
    }
} 