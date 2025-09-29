use std::time::Duration;

use indicatif::{MultiProgress, ProgressStyle};

pub fn call_with_progress<T>(
    m: &Option<MultiProgress>, name: &str, index: usize, total: usize,
    f: impl FnOnce(T) -> anyhow::Result<()>, args: T,
) -> anyhow::Result<()> {
    let pb = m.as_ref().map(|m| {
        let pb = m.add(indicatif::ProgressBar::new_spinner())
            .with_style(ProgressStyle::with_template("{prefix} {spinner} {msg}").unwrap())
            .with_prefix(format!("  [{}/{}]", index, total))
            .with_message(format!("{}: working...", name));
        pb.enable_steady_tick(Duration::from_millis(50));
        pb
    });

    f(args)?;

    if let Some(pb) = &pb {
        pb.finish_with_message(format!("{}: done", name));
    }

    Ok(())
}
