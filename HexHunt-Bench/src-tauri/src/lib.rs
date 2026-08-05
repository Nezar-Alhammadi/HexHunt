mod bench;
mod lab;
mod store;

use bench::BenchState;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let app_data = app.path().app_data_dir()?;
            std::fs::create_dir_all(&app_data)?;
            let store = store::BenchStore::open(&app_data.join("hexhunt-recon-bench-v1.sqlite3"))
                .map_err(std::io::Error::other)?;
            app.manage(BenchState::new(store));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            bench::bench_status,
            bench::list_bench_cases,
            bench::list_bench_results,
            bench::run_bench_case
        ])
        .run(tauri::generate_context!())
        .expect("error while running HexHunt Bench");
}
