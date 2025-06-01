use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::fs;
use std::io::BufRead;

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub name: String,
    pub duration: Duration,
    pub memory_usage: u64,
    pub cpu_usage: f64,
    pub operations_per_second: f64,
}

pub struct BenchmarkSystem {
    results: Arc<Mutex<HashMap<String, Vec<BenchmarkResult>>>>,
    current_benchmark: Arc<Mutex<Option<(String, Instant)>>>,
    pid: u32,
}

impl BenchmarkSystem {
    pub fn new() -> Self {
        Self {
            results: Arc::new(Mutex::new(HashMap::new())),
            current_benchmark: Arc::new(Mutex::new(None)),
            pid: std::process::id(),
        }
    }

    pub fn start_benchmark(&self, name: &str) {
        if let Ok(mut current) = self.current_benchmark.lock() {
            *current = Some((name.to_string(), Instant::now()));
        }
    }

    pub fn end_benchmark(&self, operations: u64) -> Option<BenchmarkResult> {
        if let Ok(mut current) = self.current_benchmark.lock() {
            if let Some((name, start_time)) = current.take() {
                let duration = start_time.elapsed();
                let ops_per_second = operations as f64 / duration.as_secs_f64();
                
                let cpu_usage = self.measure_cpu_usage();
                let memory_usage = self.measure_memory_usage();

                let result = BenchmarkResult {
                    name: name.clone(),
                    duration,
                    memory_usage,
                    cpu_usage,
                    operations_per_second: ops_per_second,
                };

                if let Ok(mut results) = self.results.lock() {
                    results
                        .entry(name)
                        .or_insert_with(Vec::new)
                        .push(result.clone());
                }

                return Some(result);
            }
        }
        None
    }

    fn measure_cpu_usage(&self) -> f64 {
        let stat_path = format!("/proc/{}/stat", self.pid);
        if let Ok(content) = fs::read_to_string(stat_path) {
            let fields: Vec<&str> = content.split_whitespace().collect();
            if fields.len() > 13 {
                let utime: u64 = fields[13].parse().unwrap_or(0);
                let stime: u64 = fields[14].parse().unwrap_or(0);
                return (utime + stime) as f64 / 100.0;
            }
        }
        0.0
    }

    fn measure_memory_usage(&self) -> u64 {
        let status_path = format!("/proc/{}/status", self.pid);
        if let Ok(file) = fs::File::open(status_path) {
            let reader = std::io::BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    if line.starts_with("VmRSS:") {
                        if let Some(kb) = line.split_whitespace().nth(1) {
                            if let Ok(kb) = kb.parse::<u64>() {
                                return kb * 1024; // Conversion en bytes
                            }
                        }
                    }
                }
            }
        }
        0
    }

    pub fn get_benchmark_results(&self, name: &str) -> Vec<BenchmarkResult> {
        self.results
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_all_results(&self) -> HashMap<String, Vec<BenchmarkResult>> {
        self.results.lock().unwrap().clone()
    }

    pub fn clear_results(&self) {
        if let Ok(mut results) = self.results.lock() {
            results.clear();
        }
    }

    pub fn format_results(&self) -> String {
        let mut output = String::new();
        if let Ok(results) = self.results.lock() {
            for (name, benchmarks) in results.iter() {
                output.push_str(&format!("\nBenchmark: {}\n", name));
                output.push_str("----------------------------------------\n");
                
                for (i, result) in benchmarks.iter().enumerate() {
                    output.push_str(&format!(
                        "Run {}:\n\
                         Duration: {:?}\n\
                         Operations/sec: {:.2}\n\
                         Memory Usage: {} bytes\n\
                         CPU Usage: {:.1}%\n",
                        i + 1,
                        result.duration,
                        result.operations_per_second,
                        result.memory_usage,
                        result.cpu_usage
                    ));
                }
                output.push_str("----------------------------------------\n");
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_benchmark() {
        let benchmark = BenchmarkSystem::new();
        benchmark.start_benchmark("test_operation");
        
        // Simuler une opération
        thread::sleep(Duration::from_millis(100));
        
        if let Some(result) = benchmark.end_benchmark(1000) {
            assert_eq!(result.name, "test_operation");
            assert!(result.duration >= Duration::from_millis(100));
            assert!(result.operations_per_second > 0.0);
        } else {
            panic!("Benchmark result should be Some");
        }
    }

    #[test]
    fn test_multiple_runs() {
        let benchmark = BenchmarkSystem::new();
        
        for i in 0..3 {
            benchmark.start_benchmark("multi_run");
            thread::sleep(Duration::from_millis(50));
            benchmark.end_benchmark(100);
        }

        let results = benchmark.get_benchmark_results("multi_run");
        assert_eq!(results.len(), 3);
    }
} 