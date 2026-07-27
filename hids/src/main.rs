use notify::{Watcher, RecursiveMode, Result};
use std::path::Path;
use chrono::Utc;
use serde::Serialize;

#[derive(Serialize)]
struct HidsAlert {
    timestamp: String,
    event_type: String,
    path: String,
    severity: String,
}

fn main() -> Result<()> {
    println!("Sentinel HIDS starting..");

    // channel to receive events
    let (tx, rx) = std::sync::mpsc::channel();

    // initialize the watcher
    let mut watcher = notify::recommended_watcher(tx)?;

    // current directory for now
    let path_to_watch = ".";
    watcher.watch(Path::new(path_to_watch), RecursiveMode::Recursive)?;

    println!("Monitoring directory: {} (Recursive)", path_to_watch);

    for res in rx {
        match res {
            Ok(event) => {
                let alert = HidsAlert {
                    timestamp: Utc::now().to_rfc3339(),
                    event_type: format!("{:?}", event.kind),
                    path: event.paths[0].to_string_lossy().into_owned(),
                    severity: "MEDIUM".to_string(),
                };
                println!("{}", serde_json::to_string(&alert).unwrap());
            }
            Err(e) => println!("Watch error: {:?}", e),
        }
    }

    Ok(())
}
