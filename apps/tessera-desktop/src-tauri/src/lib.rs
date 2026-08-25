mod owner;

use std::path::PathBuf;

use owner::{DesktopCapabilities, LockResult, OwnerSafeError, OwnerState, SanitizedOverview};
use tauri::State;

#[tauri::command]
fn desktop_capabilities(state: State<'_, OwnerState>) -> DesktopCapabilities {
    state.capabilities()
}

#[tauri::command(rename_all = "camelCase")]
fn open_vault(
    state: State<'_, OwnerState>,
    vault_path: String,
    passphrase: String,
) -> Result<SanitizedOverview, OwnerSafeError> {
    state.open(&PathBuf::from(vault_path), passphrase)
}

#[tauri::command]
fn lock_vault(state: State<'_, OwnerState>) -> Result<LockResult, OwnerSafeError> {
    state.lock()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(OwnerState::default())
        .invoke_handler(tauri::generate_handler![
            desktop_capabilities,
            open_vault,
            lock_vault
        ])
        .run(tauri::generate_context!())
        .expect("error while running Tauri application");
}
