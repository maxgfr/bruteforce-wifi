/*!
 * Numeric password generation for WPA/WPA2 bruteforce
 *
 * Optimized for parallel processing with minimal memory allocation.
 */

/// Parallel numeric password generator for efficient bruteforce
///
/// Generates numeric passwords in parallel batches with optimal
/// chunk sizing for multi-core processors.
pub struct ParallelPasswordGenerator {
    start: u64,
    end: u64,
    length: usize,
    batch_size: usize,
}

impl ParallelPasswordGenerator {
    /// Create a new parallel generator for a specific length
    ///
    /// # Arguments
    /// * `length` - Number of digits
    /// * `threads` - Number of threads (used to optimize batch size)
    pub fn new(length: usize, threads: usize) -> Self {
        let start = 0; // Always start at 0 (e.g., 00000000)
        let end = 10u64.pow(length as u32); // Full range: 10^length

        // Optimal batch size: balance between parallelism and overhead
        // Larger batches reduce overhead and improve cache locality
        // For maximum performance, use 10000-50000 passwords per batch
        let batch_size = 50000.min((end - start) as usize / threads);
        // Ensure at least some batch size
        let batch_size = batch_size.max(1000);

        Self {
            start,
            end,
            length,
            batch_size,
        }
    }

    /// Get total number of combinations
    pub fn total_combinations(&self) -> u64 {
        self.end - self.start
    }

    /// Generate passwords in batches
    ///
    /// Returns an iterator of password batches that can be processed in parallel.
    /// Optimized for minimal allocations and maximum throughput.
    pub fn batches(&self) -> impl Iterator<Item = Vec<String>> + '_ {
        (self.start..self.end)
            .step_by(self.batch_size)
            .map(move |batch_start| {
                let batch_end = (batch_start + self.batch_size as u64).min(self.end);
                let batch_capacity = (batch_end - batch_start) as usize;
                let mut batch = Vec::with_capacity(batch_capacity);

                for num in batch_start..batch_end {
                    // Pre-allocate string with exact capacity
                    let mut s = String::with_capacity(self.length);
                    let mut n = num;
                    let mut buf = [0u8; 20]; // Max digits for u64 is 20
                    let mut pos = self.length;

                    // Build string from right to left
                    while pos > 0 {
                        pos -= 1;
                        buf[pos] = (n % 10) as u8 + b'0';
                        n /= 10;
                    }

                    // Convert to UTF-8 string (safe since we only used digits)
                    unsafe {
                        s.as_mut_vec().extend_from_slice(&buf[..self.length]);
                    }

                    batch.push(s);
                }

                batch
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generator_basic() {
        let gen = ParallelPasswordGenerator::new(2, 4);
        assert_eq!(gen.total_combinations(), 90); // 10 to 99
        assert_eq!(gen.length, 2);
    }

    #[test]
    fn test_generator_batches() {
        let gen = ParallelPasswordGenerator::new(2, 4);
        let batches: Vec<Vec<String>> = gen.batches().collect();

        assert!(!batches.is_empty());

        // First batch should start with "10"
        assert_eq!(batches[0][0], "10");
    }

    #[test]
    fn test_generator_format() {
        let gen = ParallelPasswordGenerator::new(3, 4);
        let first_batch = gen.batches().next().unwrap();

        assert_eq!(first_batch[0], "100");
        assert_eq!(first_batch[1], "101");
        assert_eq!(first_batch[2], "102");
    }
}
