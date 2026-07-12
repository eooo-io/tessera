//! Reproducible sanitized relevance-floor calibration for the v1 MiniLM model.

use tessera_core::embed::onnx;
use tessera_core::embed::EmbeddingProvider;

struct Pair {
    category: &'static str,
    relevant: bool,
    query: &'static str,
    document: &'static str,
}

const PAIRS: &[Pair] = &[
    Pair { category: "positive", relevant: true, query: "corridor fire resistance rating", document: "Fire safety requirements specify a two hour rating for corridor walls and doors." },
    Pair { category: "positive", relevant: true, query: "sourdough fermentation schedule", document: "Rye sourdough develops flavor during a long cool fermentation before baking." },
    Pair { category: "positive", relevant: true, query: "atomic sqlite transaction recovery", document: "Use BEGIN IMMEDIATE, commit the durable index, and recover an interrupted file rename." },
    Pair { category: "positive", relevant: true, query: "oauth pkce authorization flow", document: "The client creates a PKCE verifier and exchanges the authorization code for an OAuth token." },
    Pair { category: "positive", relevant: true, query: "restore encrypted backup on linux", document: "Copy the encrypted vault bundle to Linux, unlock it, verify integrity, and rebuild derived indexes." },
    Pair { category: "positive", relevant: true, query: "screenshot optical character recognition", document: "OCR extracts visible text from a screenshot so the image can be searched." },
    Pair { category: "positive", relevant: true, query: "speaker timestamps in transcript", document: "The VTT transcript preserves each speaker turn and its start and end timestamps." },
    Pair { category: "positive", relevant: true, query: "tomato greenhouse watering", document: "Drip irrigation keeps greenhouse tomatoes evenly watered during hot weather." },
    Pair { category: "positive", relevant: true, query: "invoice payment due date", document: "The customer must pay the invoice within thirty days of the issue date." },
    Pair { category: "positive", relevant: true, query: "rust dependency lock file", document: "Cargo.lock pins the resolved Rust dependency versions for reproducible builds." },
    Pair { category: "hard_negative", relevant: false, query: "receipt chain concurrent finalization", document: "A retail receipt printer connects to the checkout terminal with a USB cable." },
    Pair { category: "hard_negative", relevant: false, query: "rust dependency lock file", document: "The locksmith replaced a rusted door lock and cut two physical keys." },
    Pair { category: "hard_negative", relevant: false, query: "oauth token scope", document: "A subway token collector documented the scope of a museum exhibit." },
    Pair { category: "hard_negative", relevant: false, query: "backup restore procedure", document: "The restaurant restored an antique chair before placing it in the dining room." },
    Pair { category: "hard_negative", relevant: false, query: "embedding model dimensions", document: "The fashion model supplied body dimensions for a custom jacket." },
    Pair { category: "hard_negative", relevant: false, query: "conversation branch selection", document: "A tree surgeon selected a damaged branch for removal." },
    Pair { category: "unrelated", relevant: false, query: "corridor fire resistance rating", document: "Blue whales migrate across the Pacific Ocean and communicate with low frequency calls." },
    Pair { category: "unrelated", relevant: false, query: "sourdough fermentation schedule", document: "The orbital period of Mars is approximately six hundred eighty seven Earth days." },
    Pair { category: "unrelated", relevant: false, query: "oauth pkce authorization flow", document: "Watercolor painters layer transparent pigments on cotton paper." },
    Pair { category: "unrelated", relevant: false, query: "restore encrypted backup on linux", document: "Honeybees use a waggle dance to indicate the direction of flowers." },
    Pair { category: "unrelated", relevant: false, query: "speaker timestamps in transcript", document: "Granite forms when magma cools slowly beneath the surface." },
    Pair { category: "unrelated", relevant: false, query: "invoice payment due date", document: "A violin string vibrates at a frequency determined by tension and length." },
];

fn cosine(left: &[f32], right: &[f32]) -> f32 {
    left.iter().zip(right).map(|(a, b)| a * b).sum()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let model_dir = onnx::default_model_dir();
    let embedder = onnx::OnnxEmbedder::load(&model_dir)?;
    let mut scored = Vec::new();
    for pair in PAIRS {
        let query = embedder.embed(pair.query)?;
        let document = embedder.embed(pair.document)?;
        let score = cosine(&query, &document);
        println!(
            "{}\t{}\t{score:.6}\t{}",
            pair.category, pair.relevant, pair.query
        );
        scored.push((score, pair.relevant));
    }

    let mut thresholds = scored.iter().map(|(score, _)| *score).collect::<Vec<_>>();
    thresholds.extend([-1.0, 1.0]);
    thresholds.sort_by(f32::total_cmp);
    thresholds.dedup();
    let mut best = (0.0_f32, 0.0_f32, 0.0_f32, -1.0_f32);
    for threshold in thresholds {
        let tp = scored.iter().filter(|(s, r)| *r && *s >= threshold).count() as f32;
        let fp = scored
            .iter()
            .filter(|(s, r)| !*r && *s >= threshold)
            .count() as f32;
        let fn_ = scored.iter().filter(|(s, r)| *r && *s < threshold).count() as f32;
        let precision = if tp + fp == 0.0 { 0.0 } else { tp / (tp + fp) };
        let recall = if tp + fn_ == 0.0 {
            0.0
        } else {
            tp / (tp + fn_)
        };
        let f1 = if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        };
        if (f1, precision, recall) > (best.0, best.1, best.2) {
            best = (f1, precision, recall, threshold);
        }
    }
    println!(
        "BEST\tthreshold={:.6}\tf1={:.3}\tprecision={:.3}\trecall={:.3}\tmodel={}",
        best.3,
        best.0,
        best.1,
        best.2,
        embedder.model_version()
    );
    Ok(())
}
