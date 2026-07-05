//! Benchmarks for the sanitizer.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use phantom_core::memory::SecretBuffer;
use phantom_sanitizer::{Sanitizer, SanitizerConfig};

fn create_secret(value: &[u8]) -> SecretBuffer {
    SecretBuffer::from_slice(value).unwrap()
}

fn benchmark_sanitize_1mb_100_secrets(c: &mut Criterion) {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());

    // Register 100 secrets
    for i in 0..100 {
        let secret_value = format!("secret_value_{:04}_abcdefgh", i);
        let secret = create_secret(secret_value.as_bytes());
        sanitizer.register_secret(&format!("KEY_{}", i), &secret);
    }

    // Generate 1MB output
    let mut output = String::with_capacity(1024 * 1024);
    for i in 0..1024 {
        output.push_str(&format!("Line {} with some random text and data content\n", i));
        if i % 100 == 0 {
            output.push_str(&format!("secret_value_{:04}_abcdefgh", i % 100));
        }
    }
    while output.len() < 1024 * 1024 {
        output.push('x');
    }

    let mut group = c.benchmark_group("sanitizer");
    group.throughput(Throughput::Bytes(output.len() as u64));

    group.bench_function("sanitize_1mb_100_secrets", |b| {
        b.iter(|| {
            sanitizer.sanitize(black_box(&output)).unwrap()
        })
    });

    group.finish();
}

fn benchmark_exact_match_only(c: &mut Criterion) {
    let mut sanitizer = Sanitizer::new(SanitizerConfig {
        detect_encoded: false,
        detect_partial: false,
        ..SanitizerConfig::fast()
    });

    for i in 0..10 {
        let secret_value = format!("secret_{}", i);
        let secret = create_secret(secret_value.as_bytes());
        sanitizer.register_secret(&format!("KEY_{}", i), &secret);
    }

    let output = "This is a test output with secret_5 in it somewhere.";

    c.bench_function("exact_match_10_secrets", |b| {
        b.iter(|| {
            sanitizer.sanitize(black_box(output)).unwrap()
        })
    });
}

fn benchmark_contains_check(c: &mut Criterion) {
    let mut sanitizer = Sanitizer::new(SanitizerConfig::fast());

    let secret = create_secret(b"mysupersecretkey123");
    sanitizer.register_secret("KEY", &secret);

    let output_with_secret = "This contains mysupersecretkey123 value";
    let output_without = "This is clean output with nothing suspicious";

    let mut group = c.benchmark_group("contains_check");

    group.bench_function("with_secret", |b| {
        b.iter(|| {
            sanitizer.contains_secret(black_box(output_with_secret))
        })
    });

    group.bench_function("without_secret", |b| {
        b.iter(|| {
            sanitizer.contains_secret(black_box(output_without))
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_sanitize_1mb_100_secrets,
    benchmark_exact_match_only,
    benchmark_contains_check
);

criterion_main!(benches);
