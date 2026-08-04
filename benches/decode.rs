use criterion::{black_box, criterion_group, criterion_main, Criterion};
use quantus_ur::{decode_bytes, decode_hex, encode_bytes_with_options, is_complete};

/// The small single-part sign request used throughout the unit tests.
fn single_part() -> Vec<String> {
    let hex_payload = "0200007416854906f03a9dff66e3270a736c44e15970ac03a638471523a03069f276ca0700e876481755010000007400000002000000";
    quantus_ur::encode_hex(hex_payload).expect("encode")
}

fn payload(len: usize) -> Vec<u8> {
    (0..len as u32).map(|i| (i % 251) as u8).collect()
}

fn bench_decode(c: &mut Criterion) {
    let single = single_part();
    // 250 bytes at 200/fragment -> 2 parts (typical small multi-part scan).
    let small_multi = encode_bytes_with_options(&payload(250), 200).expect("encode");
    // ML-DSA-87 signature + pubkey (7219 bytes) at 700/fragment -> 11 parts.
    let mldsa_multi = encode_bytes_with_options(&payload(7219), 700).expect("encode");
    // Large payload at max fragment size: 64 KiB at 4096/fragment -> 17 parts.
    let large_multi = encode_bytes_with_options(&payload(64 * 1024), 4096).expect("encode");

    let mut g = c.benchmark_group("decode");
    g.bench_function("single_part/decode_hex", |b| {
        b.iter(|| decode_hex(black_box(&single)).unwrap())
    });
    g.bench_function("single_part/decode_bytes", |b| {
        b.iter(|| decode_bytes(black_box(&single)).unwrap())
    });
    g.bench_function("single_part/is_complete", |b| {
        b.iter(|| is_complete(black_box(&single)))
    });
    g.bench_function("multi_part_2/decode_bytes", |b| {
        b.iter(|| decode_bytes(black_box(&small_multi)).unwrap())
    });
    g.bench_function("multi_part_2/is_complete", |b| {
        b.iter(|| is_complete(black_box(&small_multi)))
    });
    g.bench_function("multi_part_11/decode_bytes", |b| {
        b.iter(|| decode_bytes(black_box(&mldsa_multi)).unwrap())
    });
    g.bench_function("multi_part_11/is_complete", |b| {
        b.iter(|| is_complete(black_box(&mldsa_multi)))
    });
    g.bench_function("multi_part_17/decode_bytes", |b| {
        b.iter(|| decode_bytes(black_box(&large_multi)).unwrap())
    });
    g.bench_function("multi_part_17/is_complete", |b| {
        b.iter(|| is_complete(black_box(&large_multi)))
    });
    g.finish();

    // Simulates incremental scanning: validate + feed fragments one at a time.
    let mut g = c.benchmark_group("incremental_scan");
    g.bench_function("mldsa_11_parts", |b| {
        b.iter(|| {
            for i in 1..=mldsa_multi.len() {
                black_box(is_complete(black_box(&mldsa_multi[..i])));
            }
        })
    });
    g.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
