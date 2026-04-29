#![allow(non_snake_case)]

use dioxus::prelude::*;
use gloo_timers::future::TimeoutFuture;

use crate::tauri_api::{
    self, BackupItem, BridgePairPin, CustomField, EntryChangeRecord, ImportPreview,
    PasswordGenerationOptions, PasswordHistoryEntry, RecoverySettings, SecretEntry,
    SecretEntryInput, SecretEntryUpdateInput, SecurityQuestion, VaultData,
};

static CSS: Asset = asset!("/assets/styles.css");
static LOGIN_LOGO: Asset = asset!("/src-tauri/icons/logox128.png");

const DEFAULT_VAULT_PATH: &str = "secretsafe.vault";
#[cfg(target_arch = "wasm32")]
const LAST_VAULT_PATH_KEY: &str = "secretsafe:lastVaultPath";
#[cfg(target_arch = "wasm32")]
const THEME_KEY: &str = "secretsafe:theme";
const ALL_GROUPS: &str = "__all__";
const FAVORITES_GROUP: &str = "__favorites__";
const WEAK_GROUP: &str = "__weak__";
const REUSED_GROUP: &str = "__reused__";
const RISKY_GROUP: &str = "__risky__";
const HISTORY_GROUP: &str = "__history__";
const DEFAULT_GROUP: &str = "General";
const DEFAULT_ICON: &str = "auto";
const DEFAULT_SECRET_COLOR: &str = "#6366F1";
const AUTOLOCK_AFTER_MS: f64 = 30.0 * 60.0 * 1000.0;
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(target_arch = "wasm32")]
const APP_BUILD_FLAVOR: &str = "web";
#[cfg(not(target_arch = "wasm32"))]
const APP_BUILD_FLAVOR: &str = "desktop-local";

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthMode {
    Unlock,
    Create,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportWizardStep {
    SelectFile,
    ConfirmSelection,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SecurityModalTab {
    Audit,
    Priority,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsModalTab {
    Actions,
    Recovery,
    Info,
}

#[derive(Clone, PartialEq)]
struct VaultSession {
    path: String,
    master_password: String,
    entries: Vec<SecretEntry>,
    groups: Vec<String>,
    selected_id: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretIconKind {
    Amazon,
    Apple,
    Auto,
    Bank,
    Cart,
    Cloud,
    Code,
    Facebook,
    Game,
    Github,
    Globe,
    Google,
    Instagram,
    Key,
    Mail,
    Media,
    Microsoft,
    Netflix,
    Server,
    Social,
    Spotify,
    Youtube,
}

#[derive(Clone, Copy)]
struct IconOption {
    value: &'static str,
    label: &'static str,
    kind: SecretIconKind,
}

#[derive(Clone, PartialEq)]
struct PasswordStrength {
    level: u8,
    percent: u8,
    label: &'static str,
    hint: &'static str,
}

#[derive(Clone, PartialEq)]
struct RiskSummary {
    weak: bool,
    reused: bool,
    similar: bool,
    duplicated_domain: bool,
    exposed: bool,
    old_password: bool,
    missing_url: bool,
    missing_username: bool,
    has_history: bool,
}

#[derive(Clone, PartialEq)]
struct VaultAuditSummary {
    score: u8,
    weak_count: usize,
    reused_count: usize,
    similar_count: usize,
    duplicate_domain_count: usize,
    exposed_count: usize,
    old_password_count: usize,
}

#[derive(Clone, PartialEq)]
struct SecurityActionItem {
    entry_id: String,
    title: String,
    priority: u8,
    reasons: Vec<String>,
}

const ICON_OPTIONS: &[IconOption] = &[
    IconOption {
        value: "auto",
        label: "Auto",
        kind: SecretIconKind::Auto,
    },
    IconOption {
        value: "youtube",
        label: "YouTube",
        kind: SecretIconKind::Youtube,
    },
    IconOption {
        value: "google",
        label: "Google",
        kind: SecretIconKind::Google,
    },
    IconOption {
        value: "github",
        label: "GitHub",
        kind: SecretIconKind::Github,
    },
    IconOption {
        value: "instagram",
        label: "Instagram",
        kind: SecretIconKind::Instagram,
    },
    IconOption {
        value: "facebook",
        label: "Facebook",
        kind: SecretIconKind::Facebook,
    },
    IconOption {
        value: "netflix",
        label: "Netflix",
        kind: SecretIconKind::Netflix,
    },
    IconOption {
        value: "spotify",
        label: "Spotify",
        kind: SecretIconKind::Spotify,
    },
    IconOption {
        value: "amazon",
        label: "Amazon",
        kind: SecretIconKind::Amazon,
    },
    IconOption {
        value: "apple",
        label: "Apple",
        kind: SecretIconKind::Apple,
    },
    IconOption {
        value: "microsoft",
        label: "Microsoft",
        kind: SecretIconKind::Microsoft,
    },
    IconOption {
        value: "bank",
        label: "Banco",
        kind: SecretIconKind::Bank,
    },
    IconOption {
        value: "cart",
        label: "Compras",
        kind: SecretIconKind::Cart,
    },
    IconOption {
        value: "cloud",
        label: "Nube",
        kind: SecretIconKind::Cloud,
    },
    IconOption {
        value: "code",
        label: "Código / Dev",
        kind: SecretIconKind::Code,
    },
    IconOption {
        value: "game",
        label: "Juegos",
        kind: SecretIconKind::Game,
    },
    IconOption {
        value: "globe",
        label: "Web",
        kind: SecretIconKind::Globe,
    },
    IconOption {
        value: "key",
        label: "Llave",
        kind: SecretIconKind::Key,
    },
    IconOption {
        value: "mail",
        label: "Correo",
        kind: SecretIconKind::Mail,
    },
    IconOption {
        value: "media",
        label: "Media",
        kind: SecretIconKind::Media,
    },
    IconOption {
        value: "server",
        label: "Servidor",
        kind: SecretIconKind::Server,
    },
    IconOption {
        value: "social",
        label: "Social",
        kind: SecretIconKind::Social,
    },
];

pub fn App() -> Element {
    let mut mode = use_signal(|| AuthMode::Unlock);
    let mut vault_path = use_signal(|| DEFAULT_VAULT_PATH.to_string());
    let mut master_password = use_signal(String::new);
    let mut session = use_signal(|| None::<VaultSession>);
    let mut search = use_signal(String::new);
    let mut error_message = use_signal(String::new);
    let mut is_busy = use_signal(|| false);
    let mut is_windows_unlock_enabled = use_signal(|| false);
    let mut last_activity = use_signal(js_sys::Date::now);
    let mut is_dark_mode = use_signal(load_theme_preference);

    use_future(move || async move {
        match tauri_api::get_startup_vault_path().await {
            Ok(Some(path)) => {
                vault_path.set(path);
                return;
            }
            Ok(None) => {}
            Err(error) => error_message.set(error),
        }

        if let Some(path) = load_last_vault_path() {
            vault_path.set(path);
            return;
        }

        match tauri_api::get_default_vault_path().await {
            Ok(path) => vault_path.set(path),
            Err(error) => error_message.set(error),
        }
    });

    use_future(move || async move {
        loop {
            TimeoutFuture::new(1_000).await;

            if session.read().is_some()
                && js_sys::Date::now() - *last_activity.read() >= AUTOLOCK_AFTER_MS
            {
                session.set(None);
                master_password.set(String::new());
                search.set(String::new());
                let _ = tauri_api::clear_bridge_active_session().await;
                error_message.set("Bóveda bloqueada por inactividad.".to_string());
            }
        }
    });

    use_effect(move || {
        let path = vault_path.read().trim().to_string();
        spawn(async move {
            if path.is_empty() {
                is_windows_unlock_enabled.set(false);
                return;
            }
            match tauri_api::is_windows_unlock_enabled(&path).await {
                Ok(enabled) => is_windows_unlock_enabled.set(enabled),
                Err(_) => is_windows_unlock_enabled.set(false),
            }
        });
    });

    let unlock_or_create = move |_| async move {
        if vault_path.read().trim().is_empty() || master_password.read().is_empty() {
            error_message.set("Indica ruta de bóveda y contraseña maestra.".to_string());
            return;
        }

        is_busy.set(true);
        error_message.set(String::new());

        let path = vault_path.read().clone();
        let password = master_password.read().clone();
        let result = match *mode.read() {
            AuthMode::Create => match tauri_api::create_vault(&path, &password).await {
                Ok(_) => tauri_api::unlock_vault(&path, &password).await,
                Err(error) => Err(error),
            },
            AuthMode::Unlock => tauri_api::unlock_vault(&path, &password).await,
        };

        match result {
            Ok(vault) => {
                let selected_id = vault.entries.first().map(|entry| entry.id.clone());
                save_last_vault_path(&path);
                let _ = tauri_api::set_bridge_active_session(&path, &password).await;
                match tauri_api::is_windows_unlock_enabled(&path).await {
                    Ok(enabled) => is_windows_unlock_enabled.set(enabled),
                    Err(_) => is_windows_unlock_enabled.set(false),
                }
                session.set(Some(VaultSession {
                    path,
                    master_password: password,
                    entries: vault.entries,
                    groups: vault.groups,
                    selected_id,
                }));
            }
            Err(error) => error_message.set(error),
        }

        is_busy.set(false);
    };

    let lock_vault = move |_| {
        session.set(None);
        master_password.set(String::new());
        search.set(String::new());
        error_message.set(String::new());
        spawn(async move {
            let _ = tauri_api::clear_bridge_active_session().await;
        });
    };
    let toggle_theme = move |_| {
        let next_theme = !*is_dark_mode.read();
        is_dark_mode.set(next_theme);
        save_theme_preference(next_theme);
    };
    let app_class = if *is_dark_mode.read() {
        "h-screen overflow-hidden bg-vault-950 text-vault-50"
    } else {
        "h-screen overflow-hidden bg-white text-vault-950"
    };
    let glow_class = if *is_dark_mode.read() {
        "absolute inset-0 bg-[radial-gradient(circle_at_top_left,_rgba(59,130,246,0.28),_transparent_34%),radial-gradient(circle_at_bottom_right,_rgba(74,222,128,0.16),_transparent_32%)]"
    } else {
        "hidden"
    };

    rsx! {
        link { rel: "stylesheet", href: CSS }
        main {
            class: "{app_class}",
            tabindex: "0",
            onmousemove: move |_| last_activity.set(js_sys::Date::now()),
            onkeydown: move |_| last_activity.set(js_sys::Date::now()),
            onclick: move |_| last_activity.set(js_sys::Date::now()),
            div { class: "{glow_class}" }
            div { class: "relative h-full p-0",
                match session.read().as_ref() {
                    Some(active_session) => rsx! {
                        VaultWorkspace {
                            session: active_session.clone(),
                            search: search.read().clone(),
                            error_message: error_message.read().clone(),
                            is_dark_mode: *is_dark_mode.read(),
                            on_search: move |value| search.set(value),
                            on_lock: lock_vault,
                            on_theme_toggle: toggle_theme,
                            on_select: move |id| {
                                session.with_mut(|current| {
                                    if let Some(current) = current {
                                        current.selected_id = Some(id);
                                    }
                                });
                            },
                            on_error: move |message| error_message.set(message),
                            on_master_password_changed: move |new_password| {
                                session.with_mut(|current| {
                                    if let Some(current) = current {
                                        current.master_password = new_password;
                                    }
                                });
                            },
                            on_vault_changed: move |vault: VaultData| {
                                session.with_mut(|current| {
                                    if let Some(current) = current {
                                        let selected_exists = current
                                            .selected_id
                                            .as_ref()
                                            .is_some_and(|id| vault.entries.iter().any(|entry| &entry.id == id));
                                        current.selected_id = if selected_exists {
                                            current.selected_id.clone()
                                        } else {
                                            vault.entries.first().map(|entry| entry.id.clone())
                                        };
                                        current.entries = vault.entries;
                                        current.groups = vault.groups;
                                    }
                                });
                            }
                        }
                    },
                    None => rsx! {
                        LockedVault {
                            mode: *mode.read(),
                            vault_path: vault_path.read().clone(),
                            master_password: master_password.read().clone(),
                            error_message: error_message.read().clone(),
                            is_busy: *is_busy.read(),
                            is_dark_mode: *is_dark_mode.read(),
                            on_mode: move |next_mode| {
                                mode.set(next_mode);
                                error_message.set(String::new());
                            },
                            on_theme_toggle: toggle_theme,
                            on_path: move |value| vault_path.set(value),
                            on_password: move |value| master_password.set(value),
                            on_pick_open: move |_| async move {
                                match tauri_api::pick_vault_file().await {
                                    Ok(Some(path)) => {
                                        save_last_vault_path(&path);
                                        vault_path.set(path);
                                        mode.set(AuthMode::Unlock);
                                        error_message.set(String::new());
                                    }
                                    Ok(None) => {}
                                    Err(error) => error_message.set(error),
                                }
                            },
                            on_pick_save: move |_| async move {
                                match tauri_api::choose_vault_save_path().await {
                                    Ok(Some(path)) => {
                                        save_last_vault_path(&path);
                                        vault_path.set(path);
                                        mode.set(AuthMode::Create);
                                        error_message.set(String::new());
                                    }
                                    Ok(None) => {}
                                    Err(error) => error_message.set(error),
                                }
                            },
                            is_windows_unlock_enabled: *is_windows_unlock_enabled.read(),
                            on_unlock_windows: move |_| async move {
                                let path = vault_path.read().clone();
                                if path.trim().is_empty() {
                                    error_message.set("Indica la ruta de la bóveda.".to_string());
                                    return;
                                }
                                is_busy.set(true);
                                error_message.set(String::new());
                                match tauri_api::unlock_vault_with_windows(&path).await {
                                    Ok(result) => {
                                        let selected_id = result
                                            .vault
                                            .entries
                                            .first()
                                            .map(|entry| entry.id.clone());
                                        session.set(Some(VaultSession {
                                            path: path.clone(),
                                            master_password: result.master_password.clone(),
                                            entries: result.vault.entries,
                                            groups: result.vault.groups,
                                            selected_id,
                                        }));
                                        let _ = tauri_api::set_bridge_active_session(
                                            &path,
                                            &result.master_password,
                                        )
                                        .await;
                                    }
                                    Err(error) => error_message.set(error),
                                }
                                is_busy.set(false);
                            },
                            on_enable_windows: move |_| async move {
                                let path = vault_path.read().clone();
                                let password = master_password.read().clone();
                                if path.trim().is_empty() || password.is_empty() {
                                    error_message.set("Indica ruta y contraseña maestra para activar Windows.".to_string());
                                    return;
                                }
                                is_busy.set(true);
                                error_message.set(String::new());
                                match tauri_api::enable_windows_unlock(&path, &password).await {
                                    Ok(_) => {
                                        is_windows_unlock_enabled.set(true);
                                        error_message.set(String::new());
                                    }
                                    Err(error) => error_message.set(error),
                                }
                                is_busy.set(false);
                            },
                            on_disable_windows: move |_| async move {
                                let path = vault_path.read().clone();
                                if path.trim().is_empty() {
                                    error_message.set("Indica la ruta de la bóveda.".to_string());
                                    return;
                                }
                                is_busy.set(true);
                                error_message.set(String::new());
                                match tauri_api::disable_windows_unlock(&path).await {
                                    Ok(_) => {
                                        is_windows_unlock_enabled.set(false);
                                    }
                                    Err(error) => error_message.set(error),
                                }
                                is_busy.set(false);
                            },
                            on_submit: unlock_or_create
                        }
                    },
                }
            }
        }
    }
}

#[component]
fn LockedVault(
    mode: AuthMode,
    vault_path: String,
    master_password: String,
    error_message: String,
    is_busy: bool,
    is_dark_mode: bool,
    on_mode: EventHandler<AuthMode>,
    on_theme_toggle: EventHandler<()>,
    on_path: EventHandler<String>,
    on_password: EventHandler<String>,
    on_pick_open: EventHandler<MouseEvent>,
    on_pick_save: EventHandler<MouseEvent>,
    is_windows_unlock_enabled: bool,
    on_unlock_windows: EventHandler<MouseEvent>,
    on_enable_windows: EventHandler<MouseEvent>,
    on_disable_windows: EventHandler<MouseEvent>,
    on_submit: EventHandler<()>,
) -> Element {
    let is_create = mode == AuthMode::Create;
    let headline = if is_create {
        "Crea tu bóveda cifrada"
    } else {
        "Desbloquea tu bóveda"
    };
    let subheadline = if is_create {
        "Elige dónde guardar tu bóveda y establece una contraseña maestra sólida."
    } else {
        "Ingresa tu contraseña maestra para acceder a tus secretos guardados."
    };
    let action = if is_create {
        "Crear bóveda"
    } else {
        "Desbloquear"
    };
    let mut is_master_password_visible = use_signal(|| false);

    let bg_class = if is_dark_mode {
        "min-h-screen w-full bg-vault-950"
    } else {
        "min-h-screen w-full bg-white"
    };
    let left_class = if is_dark_mode {
        "relative flex flex-col justify-between border-b border-white/[0.07] bg-vault-900 p-7 sm:p-10 lg:border-b-0 lg:border-r lg:p-12"
    } else {
        "relative flex flex-col justify-between border-b border-slate-100 bg-slate-50 p-7 sm:p-10 lg:border-b-0 lg:border-r lg:p-12"
    };
    let right_class = if is_dark_mode {
        "flex flex-col justify-center bg-vault-950 p-7 sm:p-10 lg:p-16"
    } else {
        "flex flex-col justify-center bg-white p-7 sm:p-10 lg:p-16"
    };
    let headline_class = if is_dark_mode {
        "mt-8 text-3xl font-bold tracking-tight text-white lg:text-4xl"
    } else {
        "mt-8 text-3xl font-bold tracking-tight text-vault-950 lg:text-4xl"
    };
    let subheadline_class = if is_dark_mode {
        "mt-3 text-sm leading-relaxed text-vault-400"
    } else {
        "mt-3 text-sm leading-relaxed text-vault-500"
    };
    let brand_class = if is_dark_mode {
        "text-sm font-semibold text-white"
    } else {
        "text-sm font-semibold text-vault-950"
    };
    let muted_class = if is_dark_mode {
        "text-[11px] text-vault-500"
    } else {
        "text-[11px] text-vault-400"
    };
    let tabs_wrap = if is_dark_mode {
        "mb-7 flex border-b border-white/[0.07]"
    } else {
        "mb-7 flex border-b border-slate-200"
    };
    let label_class = if is_dark_mode {
        "mb-2 block text-xs font-medium text-vault-400"
    } else {
        "mb-2 block text-xs font-medium text-vault-500"
    };
    let input_class = if is_dark_mode {
        "flex-1 border border-white/[0.08] bg-vault-950 px-4 py-3 text-sm text-white placeholder:text-vault-600 transition focus:border-brand-500 focus:outline-none"
    } else {
        "flex-1 border border-slate-200 bg-white px-4 py-3 text-sm text-vault-950 placeholder:text-slate-400 transition focus:border-brand-500 focus:outline-none"
    };
    let picker_class = if is_dark_mode {
        "shrink-0 border border-white/[0.08] bg-vault-800 px-4 py-3 text-sm font-medium text-vault-300 transition hover:bg-vault-700 hover:text-white"
    } else {
        "shrink-0 border border-slate-200 bg-slate-50 px-4 py-3 text-sm font-medium text-vault-600 transition hover:bg-slate-100"
    };
    let pw_wrap = if is_dark_mode {
        "flex overflow-hidden border border-white/[0.08] bg-vault-950 transition focus-within:border-brand-500"
    } else {
        "flex overflow-hidden border border-slate-200 bg-white transition focus-within:border-brand-500"
    };
    let pw_input = if is_dark_mode {
        "min-w-0 flex-1 bg-transparent px-4 py-3 text-sm text-white placeholder:text-vault-600 focus:outline-none"
    } else {
        "min-w-0 flex-1 bg-transparent px-4 py-3 text-sm text-vault-950 placeholder:text-slate-400 focus:outline-none"
    };
    let eye_btn = if is_dark_mode {
        "grid w-11 shrink-0 place-items-center border-l border-white/[0.08] text-vault-500 transition hover:bg-white/5 hover:text-vault-200"
    } else {
        "grid w-11 shrink-0 place-items-center border-l border-slate-200 text-slate-400 transition hover:bg-slate-50 hover:text-vault-600"
    };
    let theme_btn = if is_dark_mode {
        "flex items-center gap-1.5 border border-white/[0.08] px-3 py-1.5 text-[11px] font-medium text-vault-400 transition hover:border-white/20 hover:text-white"
    } else {
        "flex items-center gap-1.5 border border-slate-200 px-3 py-1.5 text-[11px] font-medium text-vault-500 transition hover:border-slate-300 hover:text-vault-700"
    };
    let lock_box = if is_dark_mode {
        "flex h-14 w-14 items-center justify-center border border-brand-500/25 bg-brand-500/[0.08]"
    } else {
        "flex h-14 w-14 items-center justify-center border border-brand-200 bg-brand-50"
    };
    let lock_icon = if is_dark_mode { "h-6 w-6 text-brand-400" } else { "h-6 w-6 text-brand-600" };
    let divider = if is_dark_mode { "my-8 border-t border-white/[0.06]" } else { "my-8 border-t border-slate-100" };
    let badge_label = if is_dark_mode {
        "mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-vault-500"
    } else {
        "mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-vault-400"
    };
    let badge_a = if is_dark_mode {
        "border border-mint-300/20 bg-mint-300/[0.06] px-2.5 py-1 text-[11px] font-medium text-mint-300"
    } else {
        "border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-[11px] font-medium text-emerald-700"
    };
    let badge_b = if is_dark_mode {
        "border border-brand-400/20 bg-brand-400/[0.06] px-2.5 py-1 text-[11px] font-medium text-brand-300"
    } else {
        "border border-blue-200 bg-blue-50 px-2.5 py-1 text-[11px] font-medium text-blue-700"
    };
    let badge_c = if is_dark_mode {
        "border border-white/[0.06] bg-white/[0.03] px-2.5 py-1 text-[11px] font-medium text-vault-400"
    } else {
        "border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-600"
    };
    let form_heading = if is_dark_mode {
        "text-xl font-semibold text-white"
    } else {
        "text-xl font-semibold text-vault-950"
    };
    let form_hint = if is_dark_mode { "mt-1 text-xs text-vault-500" } else { "mt-1 text-xs text-vault-400" };
    let submit_class = if is_dark_mode {
        "w-full bg-brand-500 px-5 py-3.5 text-sm font-semibold text-white transition hover:bg-brand-400 disabled:cursor-not-allowed disabled:opacity-50"
    } else {
        "w-full bg-vault-950 px-5 py-3.5 text-sm font-semibold text-white transition hover:bg-vault-800 disabled:cursor-not-allowed disabled:opacity-50"
    };
    let trust_note = if is_dark_mode {
        "mt-6 flex items-center justify-center gap-2 text-[11px] text-vault-600"
    } else {
        "mt-6 flex items-center justify-center gap-2 text-[11px] text-vault-400"
    };
    let secondary_btn = if is_dark_mode {
        "w-full border border-white/[0.1] bg-vault-900 px-5 py-3 text-sm font-semibold text-vault-100 transition hover:bg-vault-800 disabled:cursor-not-allowed disabled:opacity-50"
    } else {
        "w-full border border-slate-200 bg-white px-5 py-3 text-sm font-semibold text-vault-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
    };

    rsx! {
        section { class: "min-h-screen overflow-y-auto {bg_class}",
            div { class: "grid min-h-screen lg:grid-cols-[1fr_1fr]",

                // ── Panel izquierdo — marca + hero ─────────────────────────
                div { class: "{left_class}",

                    // Destellos decorativos
                    if is_dark_mode {
                        div { class: "pointer-events-none absolute -left-40 -top-40 h-96 w-96 rounded-full bg-brand-500/[0.07] blur-3xl" }
                        div { class: "pointer-events-none absolute -bottom-28 right-0 h-80 w-80 rounded-full bg-mint-300/[0.05] blur-3xl" }
                    }

                    // Cabecera de marca
                    div { class: "relative flex items-center justify-between",
                        div { class: "flex items-center gap-3",
                            div { class: "grid h-9 w-9 place-items-center overflow-hidden",
                                img { class: "h-full w-full object-contain", src: LOGIN_LOGO, alt: "SecretSafe" }
                            }
                            div {
                                p { class: "{brand_class}", "SecretSafe" }
                                p { class: "{muted_class}", "Gestor local de contraseñas" }
                            }
                        }
                        button {
                            class: "{theme_btn}",
                            r#type: "button",
                            onclick: move |_| on_theme_toggle.call(()),
                            if is_dark_mode {
                                svg { class: "h-3 w-3", fill: "none", view_box: "0 0 24 24", stroke: "currentColor", stroke_width: "2", stroke_linecap: "round",
                                    circle { cx: "12", cy: "12", r: "5" }
                                    path { d: "M12 2v2M12 20v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M2 12h2M20 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" }
                                }
                                "Claro"
                            } else {
                                svg { class: "h-3 w-3", fill: "none", view_box: "0 0 24 24", stroke: "currentColor", stroke_width: "2", stroke_linecap: "round",
                                    path { d: "M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" }
                                }
                                "Oscuro"
                            }
                        }
                    }

                    // Bloque hero
                    div { class: "relative mt-12 lg:mt-16",
                        div { class: "{lock_box}",
                            svg { class: "{lock_icon}", fill: "none", view_box: "0 0 24 24", stroke: "currentColor", stroke_width: "1.8", stroke_linecap: "round", stroke_linejoin: "round",
                                path { d: "M12 17a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z" }
                                path { d: "M17 11V7a5 5 0 0 0-10 0v4" }
                                rect { x: "5", y: "11", width: "14", height: "10" }
                            }
                        }
                        h1 { class: "{headline_class}", "{headline}" }
                        p { class: "{subheadline_class}", "{subheadline}" }
                    }

                    // Lista de funcionalidades
                    div { class: "relative mt-8 grid gap-0.5",
                        FeatureItem { text: "Bóveda local cifrada con contraseña maestra", is_dark_mode }
                        FeatureItem { text: "Crear, editar, mover y borrar claves", is_dark_mode }
                        FeatureItem { text: "Carpetas para organizar tus secretos", is_dark_mode }
                        FeatureItem { text: "Generador de contraseñas seguras", is_dark_mode }
                        FeatureItem { text: "Portapapeles con limpieza automática", is_dark_mode }
                    }

                    // Chips de cifrado
                    div { class: "relative",
                        hr { class: "{divider}" }
                        p { class: "{badge_label}", "Cifrado de nivel militar" }
                        div { class: "flex flex-wrap gap-2",
                            span { class: "{badge_a}", "Argon2id KDF" }
                            span { class: "{badge_b}", "XChaCha20-Poly1305" }
                            span { class: "{badge_c}", "100% local · sin nube" }
                        }
                    }
                }

                // ── Panel derecho — formulario ─────────────────────────────
                div { class: "{right_class}",
                    div { class: "mx-auto w-full max-w-md",

                        // Tabs de modo
                        div { class: "{tabs_wrap}",
                            button {
                                class: mode_button_class(!is_create, is_dark_mode),
                                onclick: move |_| on_mode.call(AuthMode::Unlock),
                                "Desbloquear"
                            }
                            button {
                                class: mode_button_class(is_create, is_dark_mode),
                                onclick: move |_| on_mode.call(AuthMode::Create),
                                "Nueva bóveda"
                            }
                        }

                        // Encabezado del formulario
                        div { class: "mb-7",
                            h2 { class: "{form_heading}",
                                if is_create { "Configura tu bóveda" } else { "Accede a tu bóveda" }
                            }
                            p { class: "{form_hint}", "Tu contraseña maestra nunca sale de este dispositivo." }
                        }

                        form {
                            class: "space-y-5",
                            onsubmit: move |event| {
                                event.prevent_default();
                                on_submit.call(());
                            },

                            // Ruta de archivo
                            div {
                                label { class: "{label_class}", r#for: "vault-path", "Archivo de bóveda" }
                                div { class: "flex gap-2",
                                    input {
                                        id: "vault-path",
                                        class: "{input_class}",
                                        value: "{vault_path}",
                                        placeholder: "secretsafe.vault",
                                        oninput: move |event| on_path.call(event.value())
                                    }
                                    button {
                                        class: "{picker_class}",
                                        r#type: "button",
                                        onclick: move |event| {
                                            if is_create { on_pick_save.call(event); } else { on_pick_open.call(event); }
                                        },
                                        "Buscar"
                                    }
                                }
                            }

                            // Contraseña maestra
                            div {
                                label { class: "{label_class}", r#for: "master-pw", "Contraseña maestra" }
                                div { class: "{pw_wrap}",
                                    input {
                                        id: "master-pw",
                                        class: "{pw_input}",
                                        r#type: if *is_master_password_visible.read() { "text" } else { "password" },
                                        value: "{master_password}",
                                        placeholder: if is_create { "Mínimo 12 caracteres" } else { "Tu contraseña maestra" },
                                        oninput: move |event| on_password.call(event.value())
                                    }
                                    button {
                                        class: "{eye_btn}",
                                        r#type: "button",
                                        title: if *is_master_password_visible.read() { "Ocultar" } else { "Mostrar" },
                                        onclick: move |_| {
                                            let v = *is_master_password_visible.read();
                                            is_master_password_visible.set(!v);
                                        },
                                        EyeIcon { visible: *is_master_password_visible.read() }
                                        span { class: "sr-only",
                                            if *is_master_password_visible.read() { "Ocultar contraseña" } else { "Mostrar contraseña" }
                                        }
                                    }
                                }
                            }

                            // Error
                            if !error_message.is_empty() {
                                div { class: if is_dark_mode { "flex items-start gap-3 border border-red-500/20 bg-red-500/[0.06] px-4 py-3" } else { "flex items-start gap-3 border border-red-200 bg-red-50 px-4 py-3" },
                                    svg { class: if is_dark_mode { "mt-px h-4 w-4 shrink-0 text-red-400" } else { "mt-px h-4 w-4 shrink-0 text-red-500" },
                                        fill: "none", view_box: "0 0 24 24", stroke: "currentColor", stroke_width: "2", stroke_linecap: "round",
                                        circle { cx: "12", cy: "12", r: "10" }
                                        path { d: "M12 8v4M12 16h.01" }
                                    }
                                    p { class: if is_dark_mode { "text-sm text-red-300" } else { "text-sm text-red-700" }, "{error_message}" }
                                }
                            }

                            // Botón de acción
                            button {
                                class: "{submit_class}",
                                r#type: "submit",
                                disabled: is_busy,
                                div { class: "flex items-center justify-center gap-2",
                                    if is_busy {
                                        "Procesando..."
                                    } else {
                                        "{action}"
                                        svg { class: "h-4 w-4", fill: "none", view_box: "0 0 24 24", stroke: "currentColor", stroke_width: "2", stroke_linecap: "round", stroke_linejoin: "round",
                                            path { d: "M5 12h14M12 5l7 7-7 7" }
                                        }
                                    }
                                }
                            }

                            if !is_create {
                                if is_windows_unlock_enabled {
                                    button {
                                        class: "{secondary_btn}",
                                        r#type: "button",
                                        disabled: is_busy,
                                        onclick: move |event| on_unlock_windows.call(event),
                                        "Desbloquear con Windows (PIN / Huella / Cuenta)"
                                    }
                                    button {
                                        class: "{secondary_btn}",
                                        r#type: "button",
                                        disabled: is_busy,
                                        onclick: move |event| on_disable_windows.call(event),
                                        "Desactivar desbloqueo de Windows"
                                    }
                                } else {
                                    button {
                                        class: "{secondary_btn}",
                                        r#type: "button",
                                        disabled: is_busy,
                                        onclick: move |event| on_enable_windows.call(event),
                                        "Activar desbloqueo de Windows para esta bóveda"
                                    }
                                }
                            }
                        }

                        // Nota de confianza
                        p { class: "{trust_note}",
                            svg { class: "h-3 w-3", fill: "none", view_box: "0 0 24 24", stroke: "currentColor", stroke_width: "2", stroke_linecap: "round", stroke_linejoin: "round",
                                rect { x: "3", y: "11", width: "18", height: "11" }
                                path { d: "M7 11V7a5 5 0 0 1 10 0v4" }
                            }
                            "Sin servidores · sin nube · 100% en tu dispositivo"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn VaultWorkspace(
    session: VaultSession,
    search: String,
    error_message: String,
    is_dark_mode: bool,
    on_search: EventHandler<String>,
    on_lock: EventHandler<MouseEvent>,
    on_theme_toggle: EventHandler<()>,
    on_select: EventHandler<String>,
    on_error: EventHandler<String>,
    on_master_password_changed: EventHandler<String>,
    on_vault_changed: EventHandler<VaultData>,
) -> Element {
    let mut is_new_secret_modal_open = use_signal(|| false);
    let mut is_new_group_modal_open = use_signal(|| false);
    let mut is_import_modal_open = use_signal(|| false);
    let mut is_backup_modal_open = use_signal(|| false);
    let mut is_settings_modal_open = use_signal(|| false);
    let mut is_security_modal_open = use_signal(|| false);
    let mut is_bridge_modal_open = use_signal(|| false);
    let mut security_modal_tab = use_signal(|| SecurityModalTab::Audit);
    let mut selected_group = use_signal(|| ALL_GROUPS.to_string());
    let filtered_entries = session
        .entries
        .iter()
        .filter(|entry| filter_matches(entry, &selected_group.read(), &session.entries))
        .filter(|entry| secret_matches(entry, &search))
        .cloned()
        .collect::<Vec<_>>();
    let selected = selected_entry(&session, &filtered_entries);
    let groups = group_counts(&session.groups, &session.entries);
    let favorite_count = session
        .entries
        .iter()
        .filter(|entry| entry.favorite)
        .count();
    let weak_count = session
        .entries
        .iter()
        .filter(|entry| password_strength(&entry.password).level <= 2)
        .count();
    let reused_count = session
        .entries
        .iter()
        .filter(|entry| risk_summary(entry, &session.entries).reused)
        .count();
    let risky_count = session
        .entries
        .iter()
        .filter(|entry| entry_has_risk(entry, &session.entries))
        .count();
    let history_count = session
        .entries
        .iter()
        .filter(|entry| !entry.password_history.is_empty())
        .count();
    let audit = vault_audit_summary(&session.entries);
    let action_items = security_action_items(&session.entries);
    let workspace_class = if is_dark_mode {
        "flex min-h-full flex-col overflow-y-auto xl:h-screen xl:overflow-hidden xl:flex-row"
    } else {
        "flex min-h-full flex-col overflow-y-auto bg-white text-vault-950 xl:h-screen xl:overflow-hidden xl:flex-row"
    };
    let aside_class = if is_dark_mode {
        "scrollbar-hidden sticky top-0 z-20 flex max-h-screen w-full shrink-0 flex-col overflow-y-auto border border-white/10 bg-white/[0.06] p-4 shadow-2xl shadow-black/30 backdrop-blur-xl xl:h-screen xl:w-72"
    } else {
        "scrollbar-hidden sticky top-0 z-20 flex max-h-screen w-full shrink-0 flex-col overflow-y-auto border-r border-vault-200 bg-white p-4 shadow-xl shadow-vault-200/30 xl:h-screen xl:w-72"
    };
    let brand_text_class = if is_dark_mode {
        "text-sm font-semibold tracking-wide text-white"
    } else {
        "text-sm font-semibold tracking-wide text-vault-950"
    };
    let path_text_class = if is_dark_mode {
        "max-w-44 truncate text-xs text-vault-300"
    } else {
        "max-w-44 truncate text-xs text-vault-500"
    };
    let group_section_class = if is_dark_mode {
        "mt-4 border-t border-white/10 pt-4"
    } else {
        "mt-4 border-t border-vault-200 pt-4"
    };
    let group_title_class = if is_dark_mode {
        "text-xs font-semibold uppercase tracking-[0.22em] text-vault-500"
    } else {
        "text-xs font-semibold uppercase tracking-[0.22em] text-vault-500"
    };
    let create_group_class = if is_dark_mode {
        "text-xs font-semibold text-brand-300 transition hover:text-brand-200"
    } else {
        "text-xs font-semibold text-brand-600 transition hover:text-brand-500"
    };
    let status_card_class = if is_dark_mode {
        "mt-4 border border-mint-300/20 bg-mint-300/10 p-4 xl:mt-auto"
    } else {
        "mt-4 border border-vault-200 bg-vault-50 p-4 xl:mt-auto"
    };
    let status_title_class = if is_dark_mode {
        "text-sm font-semibold text-mint-300"
    } else {
        "text-sm font-semibold text-emerald-700"
    };
    let status_text_class = if is_dark_mode {
        "mt-1 text-xs leading-5 text-vault-300"
    } else {
        "mt-1 text-xs leading-5 text-vault-600"
    };
    let theme_button_class = if is_dark_mode {
        "mt-4 w-full border border-white/10 px-4 py-2.5 text-sm font-semibold text-vault-100 transition hover:bg-white/10"
    } else {
        "mt-4 w-full border border-vault-200 bg-white px-4 py-2.5 text-sm font-semibold text-vault-700 transition hover:bg-vault-100"
    };
    let lock_button_class = if is_dark_mode {
        "mt-2 w-full bg-white px-4 py-2.5 text-sm font-semibold text-vault-950 transition hover:bg-vault-100"
    } else {
        "mt-2 w-full bg-vault-950 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-vault-800"
    };
    let main_section_class = if is_dark_mode {
        "mt-0 flex min-w-0 flex-1 flex-col overflow-visible border border-white/10 bg-vault-900/75 shadow-2xl shadow-black/30 backdrop-blur-xl xl:ml-0 xl:mt-0 xl:min-h-0 xl:overflow-hidden"
    } else {
        "mt-0 flex min-w-0 flex-1 flex-col overflow-visible bg-white xl:ml-0 xl:mt-0 xl:min-h-0 xl:overflow-hidden"
    };
    let header_class = if is_dark_mode {
        "flex flex-col gap-4 border-b border-white/10 px-4 py-5 sm:px-6 lg:flex-row lg:items-center"
    } else {
        "flex flex-col gap-4 border-b border-vault-200 px-4 py-5 sm:px-6 lg:flex-row lg:items-center"
    };
    let header_title_class = if is_dark_mode {
        "text-2xl font-semibold tracking-tight text-white"
    } else {
        "text-2xl font-semibold tracking-tight text-vault-950"
    };
    let header_text_class = if is_dark_mode {
        "mt-1 text-sm text-vault-300"
    } else {
        "mt-1 text-sm text-vault-500"
    };
    let search_class = if is_dark_mode {
        "flex w-full items-center gap-3 border border-white/10 bg-white/[0.06] px-4 py-3 text-sm text-vault-300 lg:w-96"
    } else {
        "flex w-full items-center gap-3 border border-vault-200 bg-vault-50 px-4 py-3 text-sm text-vault-500 lg:w-96"
    };
    let search_input_class = if is_dark_mode {
        "w-full border-0 bg-transparent text-white placeholder:text-vault-500 focus:outline-none"
    } else {
        "w-full border-0 bg-transparent text-vault-950 placeholder:text-vault-400 focus:outline-none"
    };

    rsx! {
        div { class: "{workspace_class}",
            aside { class: "{aside_class}",
                div { class: "mb-4 flex items-center gap-3 xl:mb-8",
                    div { class: "grid h-11 w-11 place-items-center overflow-hidden",
                        img {
                            class: "h-full w-full object-contain",
                            src: LOGIN_LOGO,
                            alt: "SecretSafe"
                        }
                    }
                    div {
                        p { class: "{brand_text_class}", "SecretSafe" }
                        p { class: "{path_text_class}", "{session.path}" }
                    }
                }

                nav { class: "grid gap-2 sm:grid-cols-2 xl:block xl:space-y-2",
                    SidebarFilterButton {
                        label: "Todos los secretos",
                        count: session.entries.len(),
                        active: selected_group.read().as_str() == ALL_GROUPS,
                        is_dark_mode,
                        on_click: move |_| selected_group.set(ALL_GROUPS.to_string())
                    }
                    SidebarFilterButton {
                        label: "Favoritos",
                        count: favorite_count,
                        active: selected_group.read().as_str() == FAVORITES_GROUP,
                        is_dark_mode,
                        on_click: move |_| selected_group.set(FAVORITES_GROUP.to_string())
                    }
                    SidebarFilterButton {
                        label: "Con riesgos",
                        count: risky_count,
                        active: selected_group.read().as_str() == RISKY_GROUP,
                        is_dark_mode,
                        on_click: move |_| selected_group.set(RISKY_GROUP.to_string())
                    }
                    SidebarFilterButton {
                        label: "Débiles",
                        count: weak_count,
                        active: selected_group.read().as_str() == WEAK_GROUP,
                        is_dark_mode,
                        on_click: move |_| selected_group.set(WEAK_GROUP.to_string())
                    }
                    SidebarFilterButton {
                        label: "Reutilizadas",
                        count: reused_count,
                        active: selected_group.read().as_str() == REUSED_GROUP,
                        is_dark_mode,
                        on_click: move |_| selected_group.set(REUSED_GROUP.to_string())
                    }
                    SidebarFilterButton {
                        label: "Con historial",
                        count: history_count,
                        active: selected_group.read().as_str() == HISTORY_GROUP,
                        is_dark_mode,
                        on_click: move |_| selected_group.set(HISTORY_GROUP.to_string())
                    }
                }

                div { class: "{group_section_class}",
                    div { class: "mb-2 flex items-center justify-between gap-2 px-4",
                        p { class: "{group_title_class}", "Carpetas" }
                        button {
                            class: "{create_group_class}",
                            onclick: move |_| is_new_group_modal_open.set(true),
                            "+ Crear"
                        }
                    }
                    nav { class: "grid gap-2 sm:grid-cols-2 xl:block xl:space-y-2",
                        for group in groups {
                            SidebarFilterButton {
                                key: "{group.name}",
                                label: group.name.clone(),
                                count: group.count,
                                active: selected_group.read().as_str() == group.name.as_str(),
                                is_dark_mode,
                                on_click: move |_| selected_group.set(group.name.clone())
                            }
                        }
                    }
                }

                div { class: "{status_card_class}",
                    p { class: "{status_title_class}", "Bóveda desbloqueada" }
                    p { class: "{status_text_class}", "Las entradas se descifran en memoria hasta que bloquees la bóveda." }
                    button {
                        class: "{theme_button_class}",
                        onclick: move |_| is_settings_modal_open.set(true),
                        "Configuración"
                    }
                    button {
                        class: "{lock_button_class}",
                        onclick: move |event| on_lock.call(event),
                        "Bloquear bóveda"
                    }
                }
            }

            section { class: "{main_section_class}",
                header { class: "{header_class}",
                    div { class: "min-w-0 flex-1",
                        h1 { class: "{header_title_class}", "Bóveda de contraseñas" }
                        p { class: "{header_text_class}", "Busca, crea y administra credenciales cifradas." }
                    }
                    label { class: "{search_class}",
                        span { class: "text-vault-500", "/" }
                        input {
                            class: "{search_input_class}",
                            r#type: "search",
                            value: "{search}",
                            placeholder: "Buscar secretos...",
                            oninput: move |event| on_search.call(event.value())
                        }
                    }
                    button {
                        class: "w-full rounded-2xl bg-brand-500 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-brand-500/25 transition hover:bg-brand-400 sm:w-auto",
                        onclick: move |_| is_new_secret_modal_open.set(true),
                        "Nuevo secreto"
                    }
                }

                if !error_message.is_empty() {
                    p { class: "mx-6 mt-4 rounded-2xl border border-red-400/20 bg-red-400/10 px-4 py-3 text-sm text-red-200", "{error_message}" }
                }

                div { class: "grid flex-1 xl:min-h-0 xl:grid-rows-[1fr] lg:grid-cols-[360px_minmax(0,1fr)] 2xl:grid-cols-[420px_minmax(0,1fr)]",
                    SecretList {
                        entries: filtered_entries.clone(),
                        all_entries: session.entries.clone(),
                        selected_id: selected.as_ref().map(|entry| entry.id.clone()),
                        is_dark_mode,
                        on_select
                    }
                    SecretPanel {
                        session: session.clone(),
                        selected,
                        is_dark_mode,
                        on_error,
                        on_secret_moved: move |target_group: String| {
                            let current_group = selected_group.read().clone();
                            if is_folder_filter(&current_group) {
                                selected_group.set(target_group);
                            }
                        },
                        on_vault_changed
                    }
                }
            }

            if *is_new_secret_modal_open.read() {
                NewSecretModal {
                    session: session.clone(),
                    is_dark_mode,
                    on_error,
                    on_vault_changed,
                    on_close: move |_| is_new_secret_modal_open.set(false)
                }
            }

            if *is_new_group_modal_open.read() {
                CreateGroupModal {
                    session: session.clone(),
                    is_dark_mode,
                    on_error,
                    on_vault_changed,
                    on_close: move |_| is_new_group_modal_open.set(false)
                }
            }

            if *is_import_modal_open.read() {
                ImportKeePassModal {
                    session: session.clone(),
                    is_dark_mode,
                    on_error,
                    on_vault_changed,
                    on_close: move |_| is_import_modal_open.set(false)
                }
            }

            if *is_backup_modal_open.read() {
                BackupRecoveryModal {
                    session: session.clone(),
                    is_dark_mode,
                    on_error,
                    on_vault_changed,
                    on_close: move |_| is_backup_modal_open.set(false)
                }
            }

            if *is_settings_modal_open.read() {
                SettingsModal {
                    session: session.clone(),
                    is_dark_mode,
                    on_error,
                    on_master_password_changed,
                    on_theme_toggle,
                    on_open_import: move |_| { is_settings_modal_open.set(false); is_import_modal_open.set(true); },
                    on_open_backup: move |_| { is_settings_modal_open.set(false); is_backup_modal_open.set(true); },
                    on_open_security_audit: move |_| {
                        security_modal_tab.set(SecurityModalTab::Audit);
                        is_security_modal_open.set(true);
                    },
                    on_open_security_priority: move |_| {
                        security_modal_tab.set(SecurityModalTab::Priority);
                        is_security_modal_open.set(true);
                    },
                    on_open_bridge: move |_| is_bridge_modal_open.set(true),
                    on_close: move |_| is_settings_modal_open.set(false)
                }
            }

            if *is_security_modal_open.read() {
                SecurityInsightsModal {
                    audit,
                    action_items,
                    initial_tab: *security_modal_tab.read(),
                    is_dark_mode,
                    on_select,
                    on_close: move |_| is_security_modal_open.set(false)
                }
            }

            if *is_bridge_modal_open.read() {
                BridgePairModal {
                    is_dark_mode,
                    on_error,
                    on_close: move |_| is_bridge_modal_open.set(false)
                }
            }
        }
    }
}

#[component]
fn FeatureItem(text: &'static str, is_dark_mode: bool) -> Element {
    let text_class = if is_dark_mode { "text-sm text-vault-300" } else { "text-sm text-vault-600" };
    let dot_class = if is_dark_mode {
        "mt-[5px] h-1.5 w-1.5 shrink-0 rounded-full bg-brand-400"
    } else {
        "mt-[5px] h-1.5 w-1.5 shrink-0 rounded-full bg-brand-500"
    };
    rsx! {
        div { class: "flex items-start gap-3 py-2",
            span { class: "{dot_class}" }
            span { class: "{text_class}", "{text}" }
        }
    }
}

#[component]
fn SecretList(
    entries: Vec<SecretEntry>,
    all_entries: Vec<SecretEntry>,
    selected_id: Option<String>,
    is_dark_mode: bool,
    on_select: EventHandler<String>,
) -> Element {
    let list_class = if is_dark_mode {
        "flex min-h-0 flex-col overflow-visible border-b border-white/10 p-4 lg:border-b-0 lg:border-r xl:h-full xl:overflow-hidden"
    } else {
        "flex min-h-0 flex-col overflow-visible border-b border-vault-200 bg-white p-4 lg:border-b-0 lg:border-r xl:h-full xl:overflow-hidden"
    };
    let empty_class = if is_dark_mode {
        "border border-dashed border-white/10 bg-white/[0.03] p-6 text-center"
    } else {
        "border border-dashed border-vault-200 bg-vault-50 p-6 text-center"
    };
    let empty_title_class = if is_dark_mode {
        "text-sm font-medium text-white"
    } else {
        "text-sm font-medium text-vault-950"
    };
    rsx! {
        section { class: "{list_class}",
            div { class: "mb-4 flex items-center justify-between px-2",
                p { class: "text-xs font-semibold uppercase tracking-[0.28em] text-vault-400", "Secretos" }
                span { class: "text-xs text-vault-500", "{entries.len()} visibles" }
            }

            div { class: "scrollbar-hidden space-y-1.5 pr-2 xl:min-h-0 xl:flex-1 xl:overflow-y-auto",
                if entries.is_empty() {
                    div { class: "{empty_class}",
                        p { class: "{empty_title_class}", "Todavía no hay secretos" }
                        p { class: "mt-2 text-sm leading-6 text-vault-400", "Crea la primera credencial desde el panel derecho." }
                    }
                }

                for entry in entries {
                    SecretCard {
                        key: "{entry.id}",
                        entry: entry.clone(),
                        risk: risk_summary(&entry, &all_entries),
                        is_selected: selected_id.as_ref() == Some(&entry.id),
                        is_dark_mode,
                        on_select
                    }
                }
            }
        }
    }
}

#[component]
fn SecretCard(
    entry: SecretEntry,
    risk: RiskSummary,
    is_selected: bool,
    is_dark_mode: bool,
    on_select: EventHandler<String>,
) -> Element {
    let initials = initials(&entry.title);
    let icon_kind = secret_icon_kind(&entry);
    let icon_class = icon_container_class(icon_kind, "h-8 w-8 shrink-0 rounded-full shadow");
    let secret_color = normalize_secret_color(&entry.color);
    let card_class = match (is_selected, is_dark_mode) {
        (true, true) => {
            "border border-brand-400/30 bg-brand-500/15 px-3 py-2.5 text-left shadow-lg shadow-brand-500/10"
        }
        (false, true) => {
            "border border-white/10 bg-white/[0.04] px-3 py-2.5 text-left transition hover:border-white/20 hover:bg-white/[0.07]"
        }
        (true, false) => {
            "border border-brand-400/40 bg-brand-50 px-3 py-2.5 text-left shadow-lg shadow-brand-500/10"
        }
        (false, false) => {
            "border border-vault-200 bg-white px-3 py-2.5 text-left shadow-sm shadow-vault-200/50 transition hover:border-brand-200 hover:bg-vault-50"
        }
    };
    let title_class = if is_dark_mode {
        "truncate text-sm font-semibold text-white"
    } else {
        "truncate text-sm font-semibold text-vault-950"
    };
    let username_class = if is_dark_mode {
        "truncate text-xs text-vault-300"
    } else {
        "truncate text-xs text-vault-500"
    };
    let status_class = if entry.favorite {
        if is_dark_mode {
            "shrink-0 rounded-full bg-amber-300/15 px-2 py-0.5 text-[10px] font-medium text-amber-300"
        } else {
            "shrink-0 rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-medium text-amber-700"
        }
    } else if is_dark_mode {
        "shrink-0 rounded-full bg-mint-300/15 px-2 py-0.5 text-[10px] font-medium text-mint-300"
    } else {
        "shrink-0 rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-medium text-emerald-700"
    };
    let folder_class = if is_dark_mode {
        "mt-1 inline-flex max-w-full items-center truncate rounded-full bg-white/10 px-2 py-0.5 text-[10px] font-medium text-vault-300"
    } else {
        "mt-1 inline-flex max-w-full items-center truncate rounded-full bg-vault-100 px-2 py-0.5 text-[10px] font-medium text-vault-600"
    };
    let group_name = normalize_group_name(&entry.group);
    let show_group = !group_name.is_empty() && group_name != DEFAULT_GROUP;
    let risk_badge = if risk.reused {
        Some("Reutilizada")
    } else if risk.weak {
        Some("Débil")
    } else if risk.missing_url || risk.missing_username {
        Some("Incompleta")
    } else {
        None
    };
    let risk_badge_class = if is_dark_mode {
        "shrink-0 rounded-full bg-red-400/15 px-2 py-0.5 text-[10px] font-medium text-red-200"
    } else {
        "shrink-0 rounded-full bg-red-100 px-2 py-0.5 text-[10px] font-medium text-red-700"
    };
    let show_url = !entry.url.is_empty();
    let url_class = if is_dark_mode {
        "truncate text-[10px] text-vault-400"
    } else {
        "truncate text-[10px] text-vault-400"
    };

    rsx! {
        button {
            class: "{card_class} w-full",
            style: "border-left: 3px solid {secret_color};",
            onclick: move |_| on_select.call(entry.id.clone()),
            div { class: "flex items-center gap-3",
                div { class: "{icon_class}",
                    SecretIcon { kind: icon_kind }
                    span { class: "absolute -bottom-0.5 -right-0.5 grid h-3.5 min-w-3.5 place-items-center rounded-full border border-vault-900 bg-white px-0.5 text-[8px] font-black text-vault-950", "{initials}" }
                }
                div { class: "min-w-0 flex-1",
                    div { class: "flex items-center justify-between gap-2",
                        h2 { class: "{title_class}", "{entry.title}" }
                        if entry.favorite {
                            span { class: "{status_class}", "Favorito" }
                        } else if let Some(badge) = risk_badge {
                            span { class: "{risk_badge_class}", "{badge}" }
                        } else {
                            span { class: "{status_class}", "Seguro" }
                        }
                    }
                    if !entry.username.is_empty() {
                        p { class: "{username_class}", "{entry.username}" }
                    }
                    if show_url {
                        p { class: "{url_class}", "{entry.url}" }
                    }
                    if show_group {
                        span { class: "{folder_class}", "{group_name}" }
                    }
                }
            }
        }
    }
}

#[component]
fn SidebarFilterButton(
    label: String,
    count: usize,
    active: bool,
    is_dark_mode: bool,
    on_click: EventHandler<MouseEvent>,
) -> Element {
    let class = match (active, is_dark_mode) {
        (true, true) => {
            "flex w-full items-center justify-between bg-white/10 px-4 py-3 text-left text-sm font-medium text-white shadow-inner shadow-white/5"
        }
        (false, true) => {
            "flex w-full items-center justify-between px-4 py-3 text-left text-sm text-vault-300 transition hover:bg-white/5 hover:text-white"
        }
        (true, false) => {
            "flex w-full items-center justify-between bg-vault-950 px-4 py-3 text-left text-sm font-medium text-white shadow-sm shadow-vault-300/40"
        }
        (false, false) => {
            "flex w-full items-center justify-between px-4 py-3 text-left text-sm text-vault-600 transition hover:bg-vault-100 hover:text-vault-950"
        }
    };
    let count_class = if is_dark_mode {
        "rounded-full bg-brand-500/20 px-2 py-0.5 text-xs text-brand-300"
    } else {
        "rounded-full bg-brand-100 px-2 py-0.5 text-xs text-brand-600"
    };

    rsx! {
        button {
            class,
            onclick: move |event| on_click.call(event),
            span { class: "truncate", "{label}" }
            span { class: "{count_class}", "{count}" }
        }
    }
}

#[component]
fn SecretPanel(
    session: VaultSession,
    selected: Option<SecretEntry>,
    is_dark_mode: bool,
    on_error: EventHandler<String>,
    on_secret_moved: EventHandler<String>,
    on_vault_changed: EventHandler<VaultData>,
) -> Element {
    let panel_shell_class = if is_dark_mode {
        "border border-white/10 bg-white/[0.04] p-4 xl:min-h-full sm:p-6"
    } else {
        "border border-vault-200 bg-white p-4 xl:min-h-full shadow-sm shadow-vault-200/50 sm:p-6"
    };
    let empty_title_class = if is_dark_mode {
        "text-lg font-semibold text-white"
    } else {
        "text-lg font-semibold text-vault-950"
    };
    rsx! {
        section { class: "min-w-0 px-4 pt-4 sm:px-6 sm:pt-6 xl:h-full xl:min-h-0 xl:overflow-hidden",
            div { class: "scrollbar-hidden pb-4 pr-1 sm:pb-6 xl:h-full xl:min-h-0 xl:overflow-y-auto",
                div { class: "{panel_shell_class}",
                    match selected {
                        Some(entry) => rsx! {
                            SecretDetail {
                                key: "{entry.id}",
                                session: session.clone(),
                                entry,
                                is_dark_mode,
                                on_error,
                                on_secret_moved,
                                on_vault_changed
                            }
                        },
                        None => rsx! {
                            div { class: "grid h-full place-items-center text-center",
                                div {
                                    p { class: "{empty_title_class}", "Selecciona un secreto" }
                                    p { class: "mt-2 text-sm text-vault-400", "Los detalles de la credencial aparecerán aquí." }
                                }
                            }
                        },
                    }
                }
            }
        }
    }
}

#[component]
fn ModalFrame(
    title: &'static str,
    subtitle: &'static str,
    is_dark_mode: bool,
    on_close: EventHandler<()>,
    children: Element,
) -> Element {
    let backdrop_class = if is_dark_mode {
        "fixed inset-0 z-50 grid place-items-center overflow-hidden bg-vault-950/85 p-3 backdrop-blur-md sm:p-6"
    } else {
        "fixed inset-0 z-50 grid place-items-center overflow-hidden bg-vault-900/30 p-3 backdrop-blur-md sm:p-6"
    };
    let frame_class = if is_dark_mode {
        "my-2 flex max-h-[92vh] w-full max-w-2xl flex-col border border-white/[0.08] bg-vault-900 shadow-2xl shadow-black/60 overflow-hidden sm:my-6"
    } else {
        "my-2 flex max-h-[92vh] w-full max-w-2xl flex-col border border-vault-200 bg-white shadow-2xl shadow-vault-200/60 overflow-hidden sm:my-6"
    };
    let header_class = if is_dark_mode {
        "flex items-center justify-between gap-4 border-b border-white/[0.07] bg-white/[0.02] px-5 py-4 sm:px-6"
    } else {
        "flex items-center justify-between gap-4 border-b border-vault-100 bg-vault-50/60 px-5 py-4 sm:px-6"
    };
    let body_class = "scrollbar-hidden min-h-0 flex-1 overflow-y-auto px-5 py-5 sm:px-6";
    let title_class = if is_dark_mode {
        "text-base font-semibold tracking-tight text-white sm:text-lg"
    } else {
        "text-base font-semibold tracking-tight text-vault-950 sm:text-lg"
    };
    let subtitle_class = if is_dark_mode {
        "mt-0.5 text-xs text-vault-400"
    } else {
        "mt-0.5 text-xs text-vault-500"
    };
    let close_class = if is_dark_mode {
        "grid h-8 w-8 shrink-0 place-items-center text-vault-400 transition hover:bg-white/10 hover:text-white"
    } else {
        "grid h-8 w-8 shrink-0 place-items-center text-vault-400 transition hover:bg-vault-100 hover:text-vault-800"
    };
    let accent_style = if is_dark_mode {
        "height:2px;background:linear-gradient(to right,rgba(59,130,246,0.7),rgba(99,102,241,0.4),transparent);"
    } else {
        "height:2px;background:linear-gradient(to right,rgba(59,130,246,0.6),rgba(99,102,241,0.3),transparent);"
    };

    rsx! {
        div { class: "{backdrop_class}",
            div { class: "{frame_class}",
                div { style: "{accent_style}" }
                div { class: "{header_class}",
                    div { class: "min-w-0",
                        h2 { class: "{title_class}", "{title}" }
                        if !subtitle.is_empty() {
                            p { class: "{subtitle_class}", "{subtitle}" }
                        }
                    }
                    button {
                        class: "{close_class}",
                        onclick: move |_| on_close.call(()),
                        title: "Cerrar",
                        svg {
                            xmlns: "http://www.w3.org/2000/svg",
                            class: "h-4 w-4",
                            fill: "none",
                            view_box: "0 0 24 24",
                            stroke: "currentColor",
                            stroke_width: "2",
                            path {
                                stroke_linecap: "round",
                                stroke_linejoin: "round",
                                d: "M6 18L18 6M6 6l12 12"
                            }
                        }
                    }
                }
                div { class: "{body_class}",
                    {children}
                }
            }
        }
    }
}

#[component]
fn NewSecretModal(
    session: VaultSession,
    is_dark_mode: bool,
    on_error: EventHandler<String>,
    on_vault_changed: EventHandler<VaultData>,
    on_close: EventHandler<()>,
) -> Element {
    let mut title = use_signal(String::new);
    let mut username = use_signal(String::new);
    let mut password = use_signal(String::new);
    let mut url = use_signal(String::new);
    let mut notes = use_signal(String::new);
    let mut group = use_signal(|| DEFAULT_GROUP.to_string());
    let mut icon = use_signal(|| DEFAULT_ICON.to_string());
    let mut color = use_signal(|| DEFAULT_SECRET_COLOR.to_string());
    let mut custom_fields = use_signal(Vec::<CustomField>::new);
    let mut is_saving = use_signal(|| false);
    let mut is_generator_open = use_signal(|| false);
    let input_class = form_control_class(is_dark_mode);
    let label_class = form_label_class();
    let password_input_class = if is_dark_mode {
        "w-full border border-white/10 bg-vault-950/50 px-4 py-3 text-sm text-white placeholder:text-vault-500 focus:border-brand-400 focus:outline-none"
    } else {
        "w-full border border-vault-200 bg-white px-4 py-3 text-sm text-vault-950 placeholder:text-vault-400 focus:border-brand-500 focus:outline-none"
    };
    let generate_button_class = if is_dark_mode {
        "bg-brand-500 px-5 py-3 text-sm font-semibold text-white transition hover:bg-brand-400 sm:w-36"
    } else {
        "bg-brand-500 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-brand-500/20 transition hover:bg-brand-400 sm:w-36"
    };
    let textarea_class = if is_dark_mode {
        "mt-2 h-36 w-full resize-y border border-white/10 bg-vault-950/50 px-4 py-3 text-sm text-white placeholder:text-vault-500 focus:border-brand-400 focus:outline-none"
    } else {
        "mt-2 h-36 w-full resize-y border border-vault-200 bg-white px-4 py-3 text-sm text-vault-950 placeholder:text-vault-400 focus:border-brand-500 focus:outline-none"
    };

    let save_secret = {
        let vault_path = session.path.clone();
        let master_password = session.master_password.clone();
        move |_| {
            let vault_path = vault_path.clone();
            let master_password = master_password.clone();
            async move {
                if title.read().trim().is_empty() || password.read().is_empty() {
                    on_error.call("Título y contraseña son obligatorios.".to_string());
                    return;
                }

                is_saving.set(true);
                on_error.call(String::new());

                let entry = SecretEntryInput {
                    title: title.read().trim().to_string(),
                    username: username.read().trim().to_string(),
                    password: password.read().to_string(),
                    url: url.read().trim().to_string(),
                    notes: notes.read().trim().to_string(),
                    group: normalize_group_name(&group.read()),
                    icon: normalize_icon_value(&icon.read()),
                    color: normalize_secret_color(&color.read()),
                    custom_fields: normalize_custom_fields(custom_fields.read().clone()),
                };

                match tauri_api::add_entry(&vault_path, &master_password, entry).await {
                    Ok(vault) => {
                        title.set(String::new());
                        username.set(String::new());
                        password.set(String::new());
                        url.set(String::new());
                        notes.set(String::new());
                        group.set(DEFAULT_GROUP.to_string());
                        icon.set(DEFAULT_ICON.to_string());
                        color.set(DEFAULT_SECRET_COLOR.to_string());
                        custom_fields.set(Vec::new());
                        on_vault_changed.call(vault);
                        on_close.call(());
                    }
                    Err(error) => on_error.call(error),
                }

                is_saving.set(false);
            }
        }
    };

    rsx! {
        ModalFrame {
            title: "Nuevo secreto",
            subtitle: "Se guardará cifrado en tu bóveda local.",
            is_dark_mode,
            on_close,

            div { class: "grid gap-3 sm:grid-cols-2",
                FormInput { label: "Título", value: title.read().clone(), placeholder: "GitHub", is_dark_mode, on_change: move |value| title.set(value) }
                FormInput { label: "Usuario", value: username.read().clone(), placeholder: "tu@correo.com", is_dark_mode, on_change: move |value| username.set(value) }
                label { class: "block",
                    span { class: "{label_class}", "Grupo" }
                    input {
                        class: "{input_class}",
                        value: "{group}",
                        placeholder: "Selecciona o crea un grupo...",
                        list: "new-secret-group-options",
                        oninput: move |event| group.set(event.value())
                    }
                    datalist { id: "new-secret-group-options",
                        for group_name in session.groups.iter() {
                            option { key: "{group_name}", value: "{group_name}" }
                        }
                    }
                }
                SecretColorInput { value: color.read().clone(), is_dark_mode, on_change: move |value| color.set(value) }
                IconSelect { value: icon.read().clone(), is_dark_mode, on_change: move |value| icon.set(value) }
                label { class: "block sm:col-span-2",
                    span { class: "{label_class}", "Contraseña" }
                    div { class: "mt-2 flex flex-col gap-2 sm:flex-row",
                        input {
                            class: "{password_input_class}",
                            r#type: "password",
                            value: "{password}",
                            placeholder: "Contraseña segura",
                            oninput: move |event| password.set(event.value())
                        }
                        button {
                            class: "{generate_button_class}",
                            onclick: move |_| is_generator_open.set(true),
                            "Generar"
                        }
                    }
                }
                label { class: "block sm:col-span-2",
                    span { class: "{label_class}", "URL" }
                    input {
                        class: "{input_class}",
                        value: "{url}",
                        placeholder: "https://example.com",
                        oninput: move |event| url.set(event.value())
                    }
                }
            }

            CustomFieldsEditor {
                fields: custom_fields.read().clone(),
                is_dark_mode,
                on_change: move |fields| custom_fields.set(fields)
            }

            PasswordStrengthMeter { password: password.read().clone(), is_dark_mode }

            label { class: "mt-3 block",
                span { class: "{label_class}", "Notas" }
                textarea {
                    class: "{textarea_class}",
                    value: "{notes}",
                    placeholder: "Pistas de recuperación, notas de rotación...",
                    oninput: move |event| notes.set(event.value())
                }
            }

            div { class: "mt-6 flex flex-col-reverse justify-end gap-3 sm:flex-row",
                button {
                    class: "rounded-2xl border border-white/10 px-5 py-3 text-sm font-medium text-vault-200 transition hover:bg-white/10",
                    onclick: move |_| on_close.call(()),
                    "Cancelar"
                }
                button {
                    class: "rounded-2xl bg-brand-500 px-5 py-3 text-sm font-semibold text-white transition hover:bg-brand-400 disabled:opacity-60",
                    disabled: *is_saving.read(),
                    onclick: save_secret,
                    if *is_saving.read() { "Guardando..." } else { "Guardar secreto" }
                }
            }
        }

        if *is_generator_open.read() {
            PasswordGeneratorModal {
                is_dark_mode,
                on_error,
                on_generated: move |generated| {
                    password.set(generated);
                    is_generator_open.set(false);
                },
                on_close: move |_| is_generator_open.set(false)
            }
        }
    }
}

#[component]
fn CreateGroupModal(
    session: VaultSession,
    is_dark_mode: bool,
    on_error: EventHandler<String>,
    on_vault_changed: EventHandler<VaultData>,
    on_close: EventHandler<()>,
) -> Element {
    let mut group = use_signal(String::new);
    let mut is_saving = use_signal(|| false);

    let create_group = {
        let vault_path = session.path.clone();
        let master_password = session.master_password.clone();
        move |_| {
            let vault_path = vault_path.clone();
            let master_password = master_password.clone();
            async move {
                let group_name = normalize_group_name(&group.read());
                if group_name.is_empty() {
                    on_error.call("El nombre de la carpeta es obligatorio.".to_string());
                    return;
                }

                is_saving.set(true);
                on_error.call(String::new());

                match tauri_api::create_group(&vault_path, &master_password, &group_name).await {
                    Ok(vault) => {
                        on_vault_changed.call(vault);
                        on_close.call(());
                    }
                    Err(error) => on_error.call(error),
                }

                is_saving.set(false);
            }
        }
    };

    rsx! {
        ModalFrame {
            title: "Crear carpeta",
            subtitle: "Agrupa tus claves por contexto, proyecto o tipo de cuenta.",
            is_dark_mode,
            on_close,

            FormInput {
                label: "Nombre de carpeta",
                value: group.read().clone(),
                placeholder: "Trabajo, Personal, Finanzas...",
                is_dark_mode,
                on_change: move |value| group.set(value)
            }

            div { class: "mt-6 flex flex-col-reverse justify-end gap-3 sm:flex-row",
                button {
                    class: "rounded-2xl border border-white/10 px-5 py-3 text-sm font-medium text-vault-200 transition hover:bg-white/10",
                    onclick: move |_| on_close.call(()),
                    "Cancelar"
                }
                button {
                    class: "rounded-2xl bg-brand-500 px-5 py-3 text-sm font-semibold text-white transition hover:bg-brand-400 disabled:opacity-60",
                    disabled: *is_saving.read(),
                    onclick: create_group,
                    if *is_saving.read() { "Creando..." } else { "Crear carpeta" }
                }
            }
        }
    }
}

#[component]
fn ImportKeePassModal(
    session: VaultSession,
    is_dark_mode: bool,
    on_error: EventHandler<String>,
    on_vault_changed: EventHandler<VaultData>,
    on_close: EventHandler<()>,
) -> Element {
    let mut import_path = use_signal(String::new);
    let mut source_password = use_signal(String::new);
    let mut is_importing = use_signal(|| false);
    let mut modal_error = use_signal(String::new);
    let mut result_message = use_signal(String::new);
    let mut step = use_signal(|| ImportWizardStep::SelectFile);
    let mut preview = use_signal(|| None::<ImportPreview>);
    let mut selected_indices = use_signal(Vec::<usize>::new);
    let mut only_with_url = use_signal(|| false);
    let mut only_with_username = use_signal(|| false);
    let mut exclude_duplicates = use_signal(|| false);
    let label_class = form_label_class();
    let input_class = form_control_class(is_dark_mode);
    let message_class = if is_dark_mode {
        "mt-4 border border-mint-300/20 bg-mint-300/10 px-4 py-3 text-sm text-mint-200"
    } else {
        "mt-4 border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700"
    };
    let picker_button_class = if is_dark_mode {
        "border border-white/10 px-4 text-sm font-semibold text-vault-100 transition hover:bg-white/10"
    } else {
        "border border-vault-200 bg-white px-4 text-sm font-semibold text-vault-700 transition hover:bg-vault-100"
    };
    let error_class = if is_dark_mode {
        "mt-4 border border-red-400/20 bg-red-400/10 px-4 py-3 text-sm text-red-200"
    } else {
        "mt-4 border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"
    };
    let step_shell_class = if is_dark_mode {
        "rounded-2xl border border-white/10 bg-white/[0.03] p-4"
    } else {
        "rounded-2xl border border-vault-200 bg-vault-50 p-4"
    };
    let step_title_class = if is_dark_mode {
        "text-sm font-semibold text-vault-100"
    } else {
        "text-sm font-semibold text-vault-900"
    };
    let step_meta_class = if is_dark_mode {
        "mt-1 text-xs text-vault-400"
    } else {
        "mt-1 text-xs text-vault-600"
    };
    let badge_selected_class = if is_dark_mode {
        "rounded-full border border-brand-400/30 bg-brand-400/10 px-2.5 py-1 text-xs font-semibold text-brand-300"
    } else {
        "rounded-full border border-brand-200 bg-brand-50 px-2.5 py-1 text-xs font-semibold text-brand-700"
    };
    let badge_detected_class = if is_dark_mode {
        "rounded-full border border-vault-400/30 bg-vault-400/10 px-2.5 py-1 text-xs font-semibold text-vault-300"
    } else {
        "rounded-full border border-vault-200 bg-white px-2.5 py-1 text-xs font-semibold text-vault-700"
    };
    let badge_duplicate_class = if is_dark_mode {
        "rounded-full border border-amber-400/30 bg-amber-400/10 px-2.5 py-1 text-xs font-semibold text-amber-300"
    } else {
        "rounded-full border border-amber-300 bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-700"
    };
    let quick_filter_class = if is_dark_mode {
        "rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold text-vault-200 transition hover:bg-white/10"
    } else {
        "rounded-xl border border-vault-200 bg-white px-3 py-2 text-xs font-semibold text-vault-700 transition hover:bg-vault-100"
    };
    let row_class = if is_dark_mode {
        "flex items-start gap-3 border border-white/10 bg-vault-950/30 px-3 py-2"
    } else {
        "flex items-start gap-3 border border-vault-200 bg-white px-3 py-2"
    };
    let row_text_class = if is_dark_mode {
        "min-w-0 text-xs text-vault-300"
    } else {
        "min-w-0 text-xs text-vault-600"
    };
    let row_title_class = if is_dark_mode {
        "text-vault-100"
    } else {
        "text-vault-900"
    };
    let helper_text_class = if is_dark_mode {
        "mt-4 text-xs leading-5 text-vault-400"
    } else {
        "mt-4 text-xs leading-5 text-vault-600"
    };
    let secondary_button_class = if is_dark_mode {
        "rounded-2xl border border-white/10 px-5 py-3 text-sm font-medium text-vault-200 transition hover:bg-white/10"
    } else {
        "rounded-2xl border border-vault-200 bg-white px-5 py-3 text-sm font-medium text-vault-700 transition hover:bg-vault-100"
    };

    let pick_import_file = move |_| async move {
        match tauri_api::pick_import_file().await {
            Ok(Some(path)) => {
                import_path.set(path);
                modal_error.set(String::new());
                result_message.set(String::new());
                preview.set(None);
                selected_indices.set(Vec::new());
                only_with_url.set(false);
                only_with_username.set(false);
                exclude_duplicates.set(false);
                step.set(ImportWizardStep::SelectFile);
                on_error.call(String::new());
            }
            Ok(None) => {}
            Err(error) => on_error.call(error),
        }
    };

    let analyze_source = move |_| {
        async move {
            if import_path.read().trim().is_empty() {
                modal_error.set("Selecciona un archivo para analizar.".to_string());
                return;
            }
            modal_error.set(String::new());
            result_message.set(String::new());
            let selected_path = import_path.read().trim().to_string();
            match tauri_api::preview_import_source(&selected_path).await {
                Ok(data) => {
                    selected_indices.set(data.items.iter().map(|item| item.index).collect());
                    preview.set(Some(data));
                    only_with_url.set(false);
                    only_with_username.set(false);
                    exclude_duplicates.set(false);
                    step.set(ImportWizardStep::ConfirmSelection);
                }
                Err(error) => modal_error.set(error),
            }
        }
    };

    let mut toggle_entry = move |index: usize| {
        let mut values = selected_indices.read().clone();
        if values.contains(&index) {
            values.retain(|value| *value != index);
        } else {
            values.push(index);
        }
        values.sort_unstable();
        selected_indices.set(values);
    };

    let toggle_all = move |_| {
        if let Some(current_preview) = preview.read().clone() {
            if selected_indices.read().len() == current_preview.items.len() {
                selected_indices.set(Vec::new());
            } else {
                selected_indices.set(current_preview.items.iter().map(|item| item.index).collect());
            }
        }
    };

    let existing_entries_for_url = session.entries.clone();
    let existing_entries_for_username = session.entries.clone();
    let existing_entries_for_duplicates = session.entries.clone();

    let import_selected = {
        let vault_path = session.path.clone();
        let master_password = session.master_password.clone();
        move |_| {
            let vault_path = vault_path.clone();
            let master_password = master_password.clone();
            async move {
                if preview.read().is_none() {
                    modal_error.set("Primero analiza el archivo para continuar.".to_string());
                    return;
                }
                if selected_indices.read().is_empty() {
                    modal_error.set("Selecciona al menos una entrada para importar.".to_string());
                    return;
                }

                let selected_path = import_path.read().trim().to_string();
                let preview_data = preview.read().clone().unwrap_or_else(|| ImportPreview {
                    source: selected_path.clone(),
                    detected_format: String::new(),
                    total_count: 0,
                    sample_titles: Vec::new(),
                    items: Vec::new(),
                });
                let needs_password = preview_data.detected_format == "keepass";
                if needs_password && source_password.read().is_empty() {
                    modal_error.set(
                        "Para KeePass debes indicar la contraseña del archivo.".to_string(),
                    );
                    return;
                }

                is_importing.set(true);
                modal_error.set(String::new());
                result_message.set(String::new());
                on_error.call(String::new());

                let source_password_value = source_password.read().clone();
                let import_result = tauri_api::import_external_vault(
                    &vault_path,
                    &master_password,
                    &selected_path,
                    &source_password_value,
                    Some(tauri_api::ImportExternalOptions {
                        selected_indices: Some(selected_indices.read().clone()),
                    }),
                )
                .await;
                match import_result {
                    Ok(result) => {
                        let imported_count = result.summary.imported_count;
                        let skipped_count = result.summary.skipped_count;
                        on_vault_changed.call(result.vault);
                        source_password.set(String::new());
                        result_message.set(format!(
                            "Importación lista: {imported_count} secretos agregados, {skipped_count} omitidos."
                        ));
                    }
                    Err(error) => modal_error.set(error),
                }

                is_importing.set(false);
            }
        }
    };

    rsx! {
        ModalFrame {
            title: "Importar secretos",
            subtitle: "Wizard: analiza fuente, selecciona entradas y confirma importación.",
            is_dark_mode,
            on_close,

            if *step.read() == ImportWizardStep::SelectFile {
                label { class: "block",
                    span { class: "{label_class}", "Archivo de origen" }
                    div { class: "mt-2 flex flex-col gap-2 sm:flex-row",
                        input {
                            class: "{input_class}",
                            value: "{import_path}",
                            placeholder: "Selecciona .kdbx, .kdb, .1pif, .1pux o .csv",
                            oninput: move |event| {
                                import_path.set(event.value());
                                modal_error.set(String::new());
                                result_message.set(String::new());
                                preview.set(None);
                                selected_indices.set(Vec::new());
                                only_with_url.set(false);
                                only_with_username.set(false);
                                exclude_duplicates.set(false);
                                step.set(ImportWizardStep::SelectFile);
                            }
                        }
                        button {
                            class: "{picker_button_class}",
                            r#type: "button",
                            onclick: pick_import_file,
                            "Buscar"
                        }
                    }
                }

                label { class: "mt-4 block",
                    span { class: "{label_class}", "Contraseña del archivo (solo KeePass)" }
                    input {
                        class: "{input_class}",
                        r#type: "password",
                        value: "{source_password}",
                        placeholder: "Contraseña maestra del archivo",
                        oninput: move |event| {
                            source_password.set(event.value());
                            modal_error.set(String::new());
                            result_message.set(String::new());
                        }
                    }
                }
            } else if let Some(preview_data) = preview.read().clone() {
                div { class: "{step_shell_class}",
                    p { class: "{step_title_class}", "Paso 2: confirmar selección" }
                    p { class: "{step_meta_class}", "Formato: {preview_data.detected_format} | Detectadas: {preview_data.total_count} | Seleccionadas: {selected_indices.read().len()}" }
                    div { class: "mt-2 flex flex-wrap gap-2",
                        span { class: "{badge_selected_class}",
                            title: "Entradas marcadas actualmente para importar en esta operación",
                            "Seleccionadas: {selected_indices.read().len()}"
                        }
                        span { class: "{badge_detected_class}",
                            title: "Entradas detectadas en el archivo analizado antes de aplicar filtros",
                            "Detectadas: {preview_data.total_count}"
                        }
                        span { class: "{badge_duplicate_class}",
                            title: "Duplicadas en archivo: {import_duplicate_stats(&preview_data.items, &session.entries).in_file} | Ya en bóveda: {import_duplicate_stats(&preview_data.items, &session.entries).in_vault}",
                            "Duplicadas: {import_duplicate_stats(&preview_data.items, &session.entries).total}"
                        }
                    }
                    div { class: "mt-3 flex flex-wrap gap-2",
                        button {
                            class: "{quick_filter_class}",
                            r#type: "button",
                            onclick: move |_| {
                                let next_value = !*only_with_url.read();
                                only_with_url.set(next_value);
                                if let Some(current_preview) = preview.read().clone() {
                                    let mut in_file_counts =
                                        std::collections::HashMap::<String, usize>::new();
                                    for item in &current_preview.items {
                                        let key = import_preview_item_key(item);
                                        *in_file_counts.entry(key).or_insert(0) += 1;
                                    }
                                    let selected = current_preview
                                        .items
                                        .iter()
                                        .filter(|item| {
                                            (!next_value || !item.url.trim().is_empty())
                                                && (!*only_with_username.read()
                                                    || !item.username.trim().is_empty())
                                        })
                                        .filter(|item| {
                                            if !*exclude_duplicates.read() {
                                                return true;
                                            }
                                            let key = import_preview_item_key(item);
                                            let duplicated_in_file =
                                                in_file_counts.get(&key).copied().unwrap_or(0) > 1;
                                            let duplicated_in_vault = existing_entries_for_url
                                                .iter()
                                                .any(|entry| existing_entry_key(entry) == key);
                                            !duplicated_in_file && !duplicated_in_vault
                                        })
                                        .map(|item| item.index)
                                        .collect::<Vec<_>>();
                                    selected_indices.set(selected);
                                }
                            },
                            if *only_with_url.read() { "URL: activo" } else { "Solo con URL" }
                        }
                        button {
                            class: "{quick_filter_class}",
                            r#type: "button",
                            onclick: move |_| {
                                let next_value = !*only_with_username.read();
                                only_with_username.set(next_value);
                                if let Some(current_preview) = preview.read().clone() {
                                    let mut in_file_counts =
                                        std::collections::HashMap::<String, usize>::new();
                                    for item in &current_preview.items {
                                        let key = import_preview_item_key(item);
                                        *in_file_counts.entry(key).or_insert(0) += 1;
                                    }
                                    let selected = current_preview
                                        .items
                                        .iter()
                                        .filter(|item| {
                                            (!*only_with_url.read() || !item.url.trim().is_empty())
                                                && (!next_value || !item.username.trim().is_empty())
                                        })
                                        .filter(|item| {
                                            if !*exclude_duplicates.read() {
                                                return true;
                                            }
                                            let key = import_preview_item_key(item);
                                            let duplicated_in_file =
                                                in_file_counts.get(&key).copied().unwrap_or(0) > 1;
                                            let duplicated_in_vault = existing_entries_for_username
                                                .iter()
                                                .any(|entry| existing_entry_key(entry) == key);
                                            !duplicated_in_file && !duplicated_in_vault
                                        })
                                        .map(|item| item.index)
                                        .collect::<Vec<_>>();
                                    selected_indices.set(selected);
                                }
                            },
                            if *only_with_username.read() {
                                "Usuario: activo"
                            } else {
                                "Solo con usuario"
                            }
                        }
                        button {
                            class: "{quick_filter_class}",
                            r#type: "button",
                            onclick: move |_| {
                                let next_value = !*exclude_duplicates.read();
                                exclude_duplicates.set(next_value);
                                if let Some(current_preview) = preview.read().clone() {
                                    let mut in_file_counts =
                                        std::collections::HashMap::<String, usize>::new();
                                    for item in &current_preview.items {
                                        let key = import_preview_item_key(item);
                                        *in_file_counts.entry(key).or_insert(0) += 1;
                                    }
                                    let selected = current_preview
                                        .items
                                        .iter()
                                        .filter(|item| {
                                            (!*only_with_url.read() || !item.url.trim().is_empty())
                                                && (!*only_with_username.read()
                                                    || !item.username.trim().is_empty())
                                        })
                                        .filter(|item| {
                                            if !next_value {
                                                return true;
                                            }
                                            let key = import_preview_item_key(item);
                                            let duplicated_in_file =
                                                in_file_counts.get(&key).copied().unwrap_or(0) > 1;
                                            let duplicated_in_vault = existing_entries_for_duplicates
                                                .iter()
                                                .any(|entry| existing_entry_key(entry) == key);
                                            !duplicated_in_file && !duplicated_in_vault
                                        })
                                        .map(|item| item.index)
                                        .collect::<Vec<_>>();
                                    selected_indices.set(selected);
                                }
                            },
                            if *exclude_duplicates.read() {
                                "Duplicados: excluidos"
                            } else {
                                "Excluir duplicados"
                            }
                        }
                    }
                    button {
                        class: "mt-3 {quick_filter_class}",
                        r#type: "button",
                        onclick: toggle_all,
                        if selected_indices.read().len() == preview_data.items.len() {
                            "Deseleccionar todo"
                        } else {
                            "Seleccionar todo"
                        }
                    }
                    div { class: "mt-3 max-h-52 space-y-2 overflow-y-auto pr-1",
                        for item in preview_data.items.iter().cloned() {
                            label {
                                key: "{item.index}",
                                class: "{row_class}",
                                input {
                                    class: "mt-0.5 h-4 w-4 accent-brand-500",
                                    r#type: "checkbox",
                                    checked: selected_indices.read().contains(&item.index),
                                    onchange: move |_| toggle_entry(item.index)
                                }
                                span { class: "{row_text_class}",
                                    b { class: "{row_title_class}", "{item.title}" }
                                    if !item.username.is_empty() {
                                        " · {item.username}"
                                    }
                                    if !item.url.is_empty() {
                                        " · {item.url}"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if !modal_error.read().is_empty() {
                p { class: "{error_class}", "{modal_error}" }
            }

            if !result_message.read().is_empty() {
                p { class: "{message_class}", "{result_message}" }
            }

            p { class: "{helper_text_class}",
                "El archivo original no se modifica. Puedes importar solo la selección marcada."
            }

            div { class: "mt-6 flex flex-col-reverse justify-end gap-3 sm:flex-row",
                button {
                    class: "{secondary_button_class}",
                    r#type: "button",
                    onclick: move |_| {
                        if *step.read() == ImportWizardStep::ConfirmSelection {
                            step.set(ImportWizardStep::SelectFile);
                        } else {
                            on_close.call(());
                        }
                    },
                    if *step.read() == ImportWizardStep::ConfirmSelection {
                        "Volver"
                    } else {
                        "Cerrar"
                    }
                }
                if *step.read() == ImportWizardStep::SelectFile {
                    button {
                        class: "rounded-2xl bg-brand-500 px-5 py-3 text-sm font-semibold text-white transition hover:bg-brand-400 disabled:opacity-60",
                        r#type: "button",
                        disabled: *is_importing.read(),
                        onclick: analyze_source,
                        "Analizar archivo"
                    }
                } else {
                    button {
                        class: "rounded-2xl bg-brand-500 px-5 py-3 text-sm font-semibold text-white transition hover:bg-brand-400 disabled:opacity-60",
                        r#type: "button",
                        disabled: *is_importing.read(),
                        onclick: import_selected,
                        if *is_importing.read() {
                            "Importando..."
                        } else {
                            "Importar selección"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn BackupRecoveryModal(
    session: VaultSession,
    is_dark_mode: bool,
    on_error: EventHandler<String>,
    on_vault_changed: EventHandler<VaultData>,
    on_close: EventHandler<()>,
) -> Element {
    let mut backups = use_signal(Vec::<BackupItem>::new);
    let mut status_message = use_signal(String::new);
    let mut modal_error = use_signal(String::new);
    let mut is_loading = use_signal(|| false);
    let mut selected_backup = use_signal(String::new);
    let mut export_password = use_signal(String::new);
    let label_class = form_label_class();
    let input_class = form_control_class(is_dark_mode);
    let export_btn_class = if is_dark_mode {
        "flex flex-col items-start gap-1 rounded-2xl border border-white/10 bg-white/[0.03] px-4 py-3 text-left text-sm font-semibold text-vault-100 transition hover:bg-white/10"
    } else {
        "flex flex-col items-start gap-1 rounded-2xl border border-vault-200 bg-vault-50 px-4 py-3 text-left text-sm font-semibold text-vault-900 transition hover:bg-vault-100"
    };
    let export_desc_class = if is_dark_mode {
        "text-[10px] font-normal text-vault-400"
    } else {
        "text-[10px] font-normal text-vault-500"
    };
    let secondary_btn_class = if is_dark_mode {
        "rounded-2xl border border-white/10 px-4 py-2 text-sm font-semibold text-vault-100 transition hover:bg-white/10"
    } else {
        "rounded-2xl border border-vault-200 bg-vault-50 px-4 py-2 text-sm font-semibold text-vault-900 transition hover:bg-vault-100"
    };
    let section_label = if is_dark_mode {
        "mb-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-vault-500"
    } else {
        "mb-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-vault-400"
    };
    let message_class = if is_dark_mode {
        "mt-4 border border-mint-300/20 bg-mint-300/10 px-4 py-3 text-sm text-mint-200"
    } else {
        "mt-4 border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700"
    };
    let error_class = if is_dark_mode {
        "mt-4 border border-red-400/20 bg-red-400/10 px-4 py-3 text-sm text-red-200"
    } else {
        "mt-4 border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"
    };

    let refresh_backups = {
        let vault_path = session.path.clone();
        move |_| {
            let vault_path = vault_path.clone();
            async move {
                is_loading.set(true);
                match tauri_api::list_vault_backups(&vault_path).await {
                    Ok(items) => backups.set(items),
                    Err(error) => modal_error.set(error),
                }
                is_loading.set(false);
            }
        }
    };

    let export_csv = {
        let vault_path = session.path.clone();
        let master_password = session.master_password.clone();
        move |_| {
            let vault_path = vault_path.clone();
            let master_password = master_password.clone();
            async move {
                modal_error.set(String::new());
                status_message.set(String::new());
                match tauri_api::choose_export_csv_path().await {
                    Ok(Some(path)) => match tauri_api::export_vault_csv(&vault_path, &master_password, &path).await {
                        Ok(total) => status_message.set(format!("Exportación CSV completada: {total} secretos exportados.")),
                        Err(error) => modal_error.set(error),
                    },
                    Ok(None) => {}
                    Err(error) => modal_error.set(error),
                }
            }
        }
    };

    let export_encrypted = {
        let vault_path = session.path.clone();
        let master_password = session.master_password.clone();
        move |_| {
            let vault_path = vault_path.clone();
            let master_password = master_password.clone();
            async move {
                if export_password.read().trim().len() < 12 {
                    modal_error.set(
                        "La contraseña secundaria de exportación debe tener al menos 12 caracteres."
                            .to_string(),
                    );
                    return;
                }
                match tauri_api::choose_export_encrypted_path().await {
                    Ok(Some(path)) => match tauri_api::export_vault_encrypted_with_password(
                        &vault_path,
                        &master_password,
                        &export_password.read().clone(),
                        &path,
                    )
                    .await
                    {
                        Ok(()) => status_message.set("Exportación cifrada completada.".to_string()),
                        Err(error) => modal_error.set(error),
                    },
                    Ok(None) => {}
                    Err(error) => modal_error.set(error),
                }
            }
        }
    };

    let restore_selected = {
        let vault_path = session.path.clone();
        let master_password = session.master_password.clone();
        move |_| {
            let vault_path = vault_path.clone();
            let master_password = master_password.clone();
            async move {
                if selected_backup.read().trim().is_empty() {
                    modal_error.set("Selecciona un backup para restaurar.".to_string());
                    return;
                }
                match tauri_api::restore_vault_backup(
                    &vault_path,
                    &master_password,
                    &selected_backup.read().clone(),
                )
                .await
                {
                    Ok(vault) => {
                        on_vault_changed.call(vault);
                        status_message.set("Bóveda restaurada al punto seleccionado.".to_string());
                        modal_error.set(String::new());
                    }
                    Err(error) => modal_error.set(error),
                }
            }
        }
    };

    rsx! {
        ModalFrame {
            title: "Backups y continuidad",
            subtitle: "Backups versionados automáticos y recuperación punto-en-tiempo.",
            is_dark_mode,
            on_close,

            p { class: "{section_label}", "Exportar bóveda" }
            div { class: "grid gap-3 sm:grid-cols-2",
                button {
                    class: "{export_btn_class}",
                    r#type: "button",
                    onclick: export_csv,
                    span { "Exportar CSV" }
                    span { class: "{export_desc_class}", "Formato estándar, legible en Excel" }
                }
                button {
                    class: "{export_btn_class}",
                    r#type: "button",
                    onclick: export_encrypted,
                    span { "Exportar cifrado" }
                    span { class: "{export_desc_class}", "Archivo .vault con contraseña secundaria" }
                }
            }

            label { class: "mt-4 block",
                span { class: "{label_class}", "Contraseña secundaria para exportación cifrada" }
                input {
                    class: "{input_class}",
                    r#type: "password",
                    value: "{export_password}",
                    placeholder: "Mínimo 12 caracteres",
                    oninput: move |event| export_password.set(event.value())
                }
            }

            p { class: "mt-6 {section_label}", "Restaurar backup" }
            label { class: "mt-1 block",
                span { class: "{label_class}", "Backups disponibles" }
                select {
                    class: "{input_class}",
                    value: "{selected_backup}",
                    onchange: move |event| selected_backup.set(event.value()),
                    option { value: "", "Sin seleccionar" }
                    for item in backups.read().iter() {
                        option {
                            key: "{item.path}",
                            value: "{item.path}",
                            "{format_history_timestamp(item.created_at)}"
                        }
                    }
                }
            }

            div { class: "mt-3 flex gap-2",
                button {
                    class: "{secondary_btn_class}",
                    onclick: refresh_backups,
                    if *is_loading.read() { "Cargando..." } else { "Actualizar backups" }
                }
                button {
                    class: "rounded-2xl bg-brand-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-brand-400",
                    onclick: restore_selected,
                    "Restaurar backup"
                }
            }

            if !modal_error.read().is_empty() {
                p { class: "{error_class}", "{modal_error}" }
            }

            if !status_message.read().is_empty() {
                p { class: "{message_class}", "{status_message}" }
            }
        }
    }
}

#[component]
fn SettingsModal(
    session: VaultSession,
    is_dark_mode: bool,
    on_error: EventHandler<String>,
    on_master_password_changed: EventHandler<String>,
    on_theme_toggle: EventHandler<()>,
    on_open_import: EventHandler<()>,
    on_open_backup: EventHandler<()>,
    on_open_security_audit: EventHandler<()>,
    on_open_security_priority: EventHandler<()>,
    on_open_bridge: EventHandler<()>,
    on_close: EventHandler<()>,
) -> Element {
    let mut active_tab = use_signal(|| SettingsModalTab::Actions);
    let mut hint = use_signal(String::new);
    let mut q1 = use_signal(String::new);
    let mut a1 = use_signal(String::new);
    let mut q2 = use_signal(String::new);
    let mut a2 = use_signal(String::new);
    let mut q3 = use_signal(String::new);
    let mut a3 = use_signal(String::new);
    let mut current_master_password = use_signal(String::new);
    let mut new_master_password = use_signal(String::new);
    let mut confirm_new_master_password = use_signal(String::new);
    let mut status_message = use_signal(String::new);
    let mut modal_error = use_signal(String::new);
    let mut loading_recovery = use_signal(|| false);
    let mut saving_recovery = use_signal(|| false);
    let mut changing_master_password = use_signal(|| false);
    let tab_bar = if is_dark_mode {
        "-mx-5 sm:-mx-6 mb-5 flex overflow-x-hidden border-b border-white/[0.07] px-5 sm:px-6"
    } else {
        "-mx-5 sm:-mx-6 mb-5 flex overflow-x-hidden border-b border-vault-100 px-5 sm:px-6"
    };
    let tab_inactive = if is_dark_mode {
        "-mb-px border-b-2 border-transparent px-4 py-2.5 text-xs font-medium text-vault-400 transition hover:border-white/20 hover:text-white"
    } else {
        "-mb-px border-b-2 border-transparent px-4 py-2.5 text-xs font-medium text-vault-500 transition hover:border-vault-300 hover:text-vault-950"
    };
    let tab_active = if is_dark_mode {
        "-mb-px border-b-2 border-brand-400 px-4 py-2.5 text-xs font-semibold text-white"
    } else {
        "-mb-px border-b-2 border-brand-500 px-4 py-2.5 text-xs font-semibold text-vault-950"
    };
    let action_btn = if is_dark_mode {
        "flex w-full items-center justify-between border border-white/[0.08] bg-white/[0.02] px-4 py-3 text-left transition hover:bg-white/[0.06] disabled:opacity-50"
    } else {
        "flex w-full items-center justify-between border border-vault-100 bg-vault-50/60 px-4 py-3 text-left transition hover:bg-vault-100 disabled:opacity-50"
    };
    let action_title_class = if is_dark_mode {
        "text-sm font-medium text-white"
    } else {
        "text-sm font-medium text-vault-900"
    };
    let action_desc_class = if is_dark_mode {
        "text-[10px] text-vault-400"
    } else {
        "text-[10px] text-vault-500"
    };
    let section_label_class =
        "mb-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-vault-400";
    let divider_class = if is_dark_mode {
        "border-white/[0.07]"
    } else {
        "border-vault-100"
    };
    let error_class = if is_dark_mode {
        "border border-red-400/20 bg-red-400/10 px-3 py-2 text-xs text-red-200"
    } else {
        "border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700"
    };
    let success_class = if is_dark_mode {
        "border border-mint-300/20 bg-mint-300/10 px-3 py-2 text-xs text-mint-300"
    } else {
        "border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-700"
    };

    let load_recovery = {
        let vault_path = session.path.clone();
        let master_password = session.master_password.clone();
        move |_| {
            let vault_path = vault_path.clone();
            let master_password = master_password.clone();
            async move {
                loading_recovery.set(true);
                modal_error.set(String::new());
                match tauri_api::get_recovery_settings(&vault_path, &master_password).await {
                    Ok(settings) => {
                        hint.set(settings.hint);
                        let mut items = settings.security_questions.into_iter();
                        if let Some(item) = items.next() { q1.set(item.question); a1.set(item.answer_hint); }
                        if let Some(item) = items.next() { q2.set(item.question); a2.set(item.answer_hint); }
                        if let Some(item) = items.next() { q3.set(item.question); a3.set(item.answer_hint); }
                    }
                    Err(error) => {
                        modal_error.set(error.clone());
                        on_error.call(error);
                    }
                }
                loading_recovery.set(false);
            }
        }
    };

    let save_recovery = {
        let vault_path = session.path.clone();
        let master_password = session.master_password.clone();
        move |_| {
            let vault_path = vault_path.clone();
            let master_password = master_password.clone();
            async move {
                saving_recovery.set(true);
                status_message.set(String::new());
                modal_error.set(String::new());
                let questions = vec![
                    SecurityQuestion { question: q1.read().trim().to_string(), answer_hint: a1.read().trim().to_string() },
                    SecurityQuestion { question: q2.read().trim().to_string(), answer_hint: a2.read().trim().to_string() },
                    SecurityQuestion { question: q3.read().trim().to_string(), answer_hint: a3.read().trim().to_string() },
                ];
                let payload = RecoverySettings {
                    hint: hint.read().trim().to_string(),
                    security_questions: questions,
                };
                match tauri_api::update_recovery_settings(&vault_path, &master_password, payload).await {
                    Ok(_) => status_message.set("Datos de recuperación actualizados.".to_string()),
                    Err(error) => {
                        modal_error.set(error.clone());
                        on_error.call(error);
                    }
                }
                saving_recovery.set(false);
            }
        }
    };

    let change_master_password = {
        let vault_path = session.path.clone();
        move |_| {
            let vault_path = vault_path.clone();
            async move {
                let current_value = current_master_password.read().clone();
                let new_value = new_master_password.read().clone();
                let confirm_value = confirm_new_master_password.read().clone();

                if current_value.trim().is_empty()
                    || new_value.trim().is_empty()
                    || confirm_value.trim().is_empty()
                {
                    modal_error.set("Completa los tres campos para cambiar la contraseña maestra.".to_string());
                    return;
                }
                if new_value != confirm_value {
                    modal_error.set("La nueva contraseña y su confirmación no coinciden.".to_string());
                    return;
                }
                if new_value.trim().len() < 12 {
                    modal_error.set("La nueva contraseña maestra debe tener al menos 12 caracteres.".to_string());
                    return;
                }

                changing_master_password.set(true);
                status_message.set(String::new());
                modal_error.set(String::new());
                on_error.call(String::new());

                match tauri_api::change_master_password(&vault_path, &current_value, &new_value).await {
                    Ok(_) => {
                        on_master_password_changed.call(new_value.clone());
                        current_master_password.set(String::new());
                        new_master_password.set(String::new());
                        confirm_new_master_password.set(String::new());
                        status_message.set("Contraseña maestra actualizada correctamente.".to_string());
                    }
                    Err(error) => {
                        modal_error.set(error.clone());
                        on_error.call(error);
                    }
                }
                changing_master_password.set(false);
            }
        }
    };

    let open_dev_site = move |_| async move {
        let _ = tauri_api::open_url("https://afesdev.com").await;
    };

    rsx! {
        ModalFrame {
            title: "Configuración",
            subtitle: "Administra opciones de la app y continuidad de acceso.",
            is_dark_mode,
            on_close,

            // ── Tab strip ─────────────────────────────────────────────────
            div { class: "{tab_bar}",
                button {
                    class: if *active_tab.read() == SettingsModalTab::Actions { tab_active } else { tab_inactive },
                    onclick: move |_| { active_tab.set(SettingsModalTab::Actions); modal_error.set(String::new()); },
                    "Opciones"
                }
                button {
                    class: if *active_tab.read() == SettingsModalTab::Recovery { tab_active } else { tab_inactive },
                    onclick: move |_| { active_tab.set(SettingsModalTab::Recovery); modal_error.set(String::new()); spawn(load_recovery(())); },
                    "Recuperación"
                }
                button {
                    class: if *active_tab.read() == SettingsModalTab::Info { tab_active } else { tab_inactive },
                    onclick: move |_| { active_tab.set(SettingsModalTab::Info); modal_error.set(String::new()); },
                    "Información"
                }
            }

            // ── Tab: Opciones ─────────────────────────────────────────────
            if *active_tab.read() == SettingsModalTab::Actions {
                div { class: "grid gap-2 sm:grid-cols-2",
                    button { class: "{action_btn}", onclick: move |_| on_theme_toggle.call(()),
                        div {
                            p { class: "{action_title_class}", "Cambiar tema" }
                            p { class: "{action_desc_class}", "Alterna entre modo claro y oscuro" }
                        }
                        span { class: "text-vault-400 text-xs", "→" }
                    }
                    button { class: "{action_btn}", onclick: move |_| on_open_import.call(()),
                        div {
                            p { class: "{action_title_class}", "Importar / Exportar" }
                            p { class: "{action_desc_class}", "KeePass, CSV o bóveda .vault" }
                        }
                        span { class: "text-vault-400 text-xs", "→" }
                    }
                    button { class: "{action_btn}", onclick: move |_| on_open_backup.call(()),
                        div {
                            p { class: "{action_title_class}", "Backups" }
                            p { class: "{action_desc_class}", "Copias de seguridad y restauración" }
                        }
                        span { class: "text-vault-400 text-xs", "→" }
                    }
                    button { class: "{action_btn}", onclick: move |_| on_open_security_audit.call(()),
                        div {
                            p { class: "{action_title_class}", "Auditoría avanzada" }
                            p { class: "{action_desc_class}", "Métricas globales de seguridad" }
                        }
                        span { class: "text-vault-400 text-xs", "→" }
                    }
                    button { class: "{action_btn}", onclick: move |_| on_open_security_priority.call(()),
                        div {
                            p { class: "{action_title_class}", "Centro de seguridad" }
                            p { class: "{action_desc_class}", "Acciones prioritarias pendientes" }
                        }
                        span { class: "text-vault-400 text-xs", "→" }
                    }
                    button { class: "{action_btn}", onclick: move |_| on_open_bridge.call(()),
                        div {
                            p { class: "{action_title_class}", "Conectar extensión" }
                            p { class: "{action_desc_class}", "Autocompletado en el navegador" }
                        }
                        span { class: "text-vault-400 text-xs", "→" }
                    }
                }
            }

            // ── Tab: Recuperación ─────────────────────────────────────────
            if *active_tab.read() == SettingsModalTab::Recovery {
                div { class: "grid gap-0",

                    // Sub-sección: Pistas
                    p { class: "{section_label_class}", "Pistas de recuperación" }
                    p { class: "mb-3 text-xs text-vault-500", "La contraseña maestra no se puede recuperar en texto plano. Estas pistas solo te ayudan a recordarla." }
                    div { class: "grid gap-3",
                        FormInput { label: "Pista maestra", value: hint.read().clone(), placeholder: "Frase guía para recordar tu contraseña", is_dark_mode, on_change: move |value| hint.set(value) }
                        div { class: "grid gap-3 sm:grid-cols-2",
                            FormInput { label: "Pregunta 1", value: q1.read().clone(), placeholder: "¿Pregunta de seguridad?", is_dark_mode, on_change: move |value| q1.set(value) }
                            FormInput { label: "Pista 1", value: a1.read().clone(), placeholder: "Pista (no respuesta completa)", is_dark_mode, on_change: move |value| a1.set(value) }
                            FormInput { label: "Pregunta 2", value: q2.read().clone(), placeholder: "¿Pregunta de seguridad?", is_dark_mode, on_change: move |value| q2.set(value) }
                            FormInput { label: "Pista 2", value: a2.read().clone(), placeholder: "Pista (no respuesta completa)", is_dark_mode, on_change: move |value| a2.set(value) }
                            FormInput { label: "Pregunta 3", value: q3.read().clone(), placeholder: "¿Pregunta de seguridad?", is_dark_mode, on_change: move |value| q3.set(value) }
                            FormInput { label: "Pista 3", value: a3.read().clone(), placeholder: "Pista (no respuesta completa)", is_dark_mode, on_change: move |value| a3.set(value) }
                        }
                        button {
                            class: if is_dark_mode { "border border-white/10 px-4 py-2.5 text-sm font-medium text-vault-200 transition hover:bg-white/10 disabled:opacity-50" } else { "border border-vault-200 bg-white px-4 py-2.5 text-sm font-medium text-vault-700 transition hover:bg-vault-100 disabled:opacity-50" },
                            disabled: *loading_recovery.read() || *saving_recovery.read(),
                            onclick: save_recovery,
                            if *saving_recovery.read() { "Guardando..." } else { "Guardar pistas de recuperación" }
                        }
                    }

                    // Sub-sección: Contraseña maestra
                    div { class: "mt-5 border-t {divider_class} pt-5",
                        p { class: "{section_label_class}", "Contraseña maestra" }
                        div { class: "grid gap-3",
                            PasswordInput {
                                label: "Contraseña actual",
                                value: current_master_password.read().clone(),
                                placeholder: "Tu contraseña maestra actual",
                                is_dark_mode,
                                on_change: move |value| current_master_password.set(value)
                            }
                            div { class: "grid gap-3 sm:grid-cols-2",
                                PasswordInput {
                                    label: "Nueva contraseña",
                                    value: new_master_password.read().clone(),
                                    placeholder: "Mínimo 12 caracteres",
                                    is_dark_mode,
                                    on_change: move |value| new_master_password.set(value)
                                }
                                PasswordInput {
                                    label: "Confirmar nueva",
                                    value: confirm_new_master_password.read().clone(),
                                    placeholder: "Repite la nueva contraseña",
                                    is_dark_mode,
                                    on_change: move |value| confirm_new_master_password.set(value)
                                }
                            }
                            button {
                                class: if is_dark_mode { "bg-white px-4 py-2.5 text-sm font-semibold text-vault-950 transition hover:bg-vault-100 disabled:opacity-50" } else { "bg-vault-950 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-vault-800 disabled:opacity-50" },
                                disabled: *changing_master_password.read(),
                                onclick: change_master_password,
                                if *changing_master_password.read() { "Actualizando..." } else { "Actualizar contraseña maestra" }
                            }
                        }
                    }

                    if !modal_error.read().is_empty() {
                        p { class: "mt-3 {error_class}", "{modal_error}" }
                    }
                    if !status_message.read().is_empty() {
                        p { class: "mt-3 {success_class}", "{status_message}" }
                    }
                }
            }

            // ── Tab: Información ──────────────────────────────────────────
            if *active_tab.read() == SettingsModalTab::Info {
                div { class: "grid gap-4",
                    div { class: if is_dark_mode { "border border-white/[0.08] bg-white/[0.02] p-4" } else { "border border-vault-100 bg-vault-50/60 p-4" },
                        p { class: if is_dark_mode { "text-sm font-semibold text-white" } else { "text-sm font-semibold text-vault-950" }, "SecretSafe" }
                        p { class: "mt-0.5 text-xs text-vault-400", "Bóveda local cifrada · Formato .vault" }
                        p { class: "mt-1 text-xs text-vault-400", "Versión: v{APP_VERSION}" }
                        p { class: "text-xs text-vault-400", "Build: {APP_BUILD_FLAVOR}" }
                    }
                    div { class: "grid gap-2",
                        p { class: "{section_label_class}", "Características" }
                        div { class: if is_dark_mode { "grid gap-1.5 text-xs text-vault-300" } else { "grid gap-1.5 text-xs text-vault-600" },
                            p { "· Cifrado en reposo con clave derivada de tu contraseña maestra" }
                            p { "· Autocompletado mediante extensión + bridge local con sesión temporal" }
                            p { "· Sin sincronización en la nube — tus datos nunca salen de tu equipo" }
                            p { "· Historial de contraseñas y auditoría de cambios por entrada" }
                        }
                    }
                    div { class: "border-t {divider_class} pt-4",
                        p { class: "{section_label_class}", "Desarrollador" }
                        p { class: if is_dark_mode { "text-sm text-vault-300" } else { "text-sm text-vault-600" }, "AfesDev · Colombia" }
                        button {
                            class: if is_dark_mode { "mt-3 border border-white/10 px-4 py-2.5 text-sm font-medium text-brand-300 transition hover:bg-white/10" } else { "mt-3 border border-vault-200 bg-white px-4 py-2.5 text-sm font-medium text-brand-600 transition hover:bg-vault-100" },
                            onclick: open_dev_site,
                            "Visitar afesdev.com →"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn SecurityInsightsModal(
    audit: VaultAuditSummary,
    action_items: Vec<SecurityActionItem>,
    initial_tab: SecurityModalTab,
    is_dark_mode: bool,
    on_select: EventHandler<String>,
    on_close: EventHandler<()>,
) -> Element {
    let mut active_tab = use_signal(|| initial_tab);
    let tab_base_class = if is_dark_mode {
        "rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold text-vault-300 transition hover:bg-white/10"
    } else {
        "rounded-xl border border-vault-200 bg-white px-3 py-2 text-xs font-semibold text-vault-600 transition hover:bg-vault-100"
    };
    let tab_active_class = if is_dark_mode {
        "rounded-xl border border-brand-400/40 bg-brand-500/10 px-3 py-2 text-xs font-semibold text-brand-300"
    } else {
        "rounded-xl border border-brand-200 bg-brand-50 px-3 py-2 text-xs font-semibold text-brand-700"
    };

    rsx! {
        ModalFrame {
            title: "Seguridad avanzada",
            subtitle: "Revisa métricas globales y acciones prioritarias de tu bóveda.",
            is_dark_mode,
            on_close,

            div { class: "flex flex-wrap gap-2",
                button {
                    class: if *active_tab.read() == SecurityModalTab::Audit {
                        tab_active_class
                    } else {
                        tab_base_class
                    },
                    r#type: "button",
                    onclick: move |_| active_tab.set(SecurityModalTab::Audit),
                    "Auditoría"
                }
                button {
                    class: if *active_tab.read() == SecurityModalTab::Priority {
                        tab_active_class
                    } else {
                        tab_base_class
                    },
                    r#type: "button",
                    onclick: move |_| active_tab.set(SecurityModalTab::Priority),
                    "Centro de prioridad"
                }
            }

            if *active_tab.read() == SecurityModalTab::Audit {
                VaultAuditOverview {
                    audit,
                    is_dark_mode,
                    compact: true
                }
            } else {
                VaultSecurityActionCenter {
                    items: action_items,
                    is_dark_mode,
                    on_select,
                    compact: true
                }
            }
        }
    }
}

#[component]
fn BridgePairModal(
    is_dark_mode: bool,
    on_error: EventHandler<String>,
    on_close: EventHandler<()>,
) -> Element {
    let mut pair_pin = use_signal(|| None::<BridgePairPin>);
    let mut is_generating = use_signal(|| false);
    let mut modal_error = use_signal(String::new);
    let mut status_message = use_signal(String::new);
    let card_class = if is_dark_mode {
        "mt-4 border border-brand-400/20 bg-brand-500/10 p-4"
    } else {
        "mt-4 border border-brand-200 bg-brand-50 p-4"
    };
    let pin_class = if is_dark_mode {
        "mt-2 break-all border border-white/10 bg-vault-950/60 px-3 py-2 font-mono text-sm text-white"
    } else {
        "mt-2 break-all border border-vault-200 bg-white px-3 py-2 font-mono text-sm text-vault-950"
    };
    let error_class = if is_dark_mode {
        "mt-4 border border-red-400/20 bg-red-400/10 px-4 py-3 text-sm text-red-200"
    } else {
        "mt-4 border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"
    };
    let message_class = if is_dark_mode {
        "mt-4 border border-mint-300/20 bg-mint-300/10 px-4 py-3 text-sm text-mint-200"
    } else {
        "mt-4 border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700"
    };

    let generate_pin = move |_| async move {
        is_generating.set(true);
        modal_error.set(String::new());
        status_message.set(String::new());
        on_error.call(String::new());

        match tauri_api::create_bridge_pair_pin().await {
            Ok(pin) => pair_pin.set(Some(pin)),
            Err(error) => modal_error.set(error),
        }

        is_generating.set(false);
    };

    let copy_pin = move |_| async move {
        let Some(pin) = pair_pin.read().as_ref().map(|pin| pin.pin.clone()) else {
            modal_error.set("Genera un PIN primero.".to_string());
            return;
        };

        modal_error.set(String::new());
        status_message.set(String::new());
        match tauri_api::copy_secret_to_clipboard(&pin).await {
            Ok(()) => status_message.set("PIN copiado al portapapeles.".to_string()),
            Err(error) => modal_error.set(error),
        }
    };

    rsx! {
        ModalFrame {
            title: "Conectar extensión",
            subtitle: "Genera un PIN temporal para vincular la extensión de navegador.",
            is_dark_mode,
            on_close,

            p { class: "text-sm text-vault-400",
                "1) Genera PIN temporal. 2) Pégalo en la extensión. 3) Conéctala y usa autofill en el sitio actual."
            }

            div { class: "{card_class}",
                p { class: "text-xs font-semibold uppercase tracking-[0.22em] text-vault-500", "Bridge local" }
                p { class: "mt-2 text-sm text-vault-300", "Endpoint: http://127.0.0.1:47635" }
                if let Some(pin) = pair_pin.read().as_ref() {
                    p { class: "{pin_class}", "{pin.pin}" }
                    p { class: "mt-2 text-xs text-vault-400", "Expira pronto (PIN temporal)." }
                } else {
                    p { class: "mt-2 text-sm text-vault-400", "No hay PIN activo. Genera uno para emparejar la extensión." }
                }
            }

            if !modal_error.read().is_empty() {
                p { class: "{error_class}", "{modal_error}" }
            }

            if !status_message.read().is_empty() {
                p { class: "{message_class}", "{status_message}" }
            }

            div { class: "mt-6 flex flex-col-reverse justify-end gap-3 sm:flex-row",
                button {
                    class: "rounded-2xl border border-white/10 px-5 py-3 text-sm font-medium text-vault-200 transition hover:bg-white/10",
                    r#type: "button",
                    onclick: move |_| on_close.call(()),
                    "Cerrar"
                }
                button {
                    class: "rounded-2xl border border-brand-400/30 bg-brand-500/10 px-5 py-3 text-sm font-semibold text-brand-300 transition hover:bg-brand-500/20 disabled:opacity-60",
                    r#type: "button",
                    disabled: *is_generating.read(),
                    onclick: generate_pin,
                    if *is_generating.read() { "Generando..." } else { "Generar PIN temporal" }
                }
                button {
                    class: "rounded-2xl bg-white px-5 py-3 text-sm font-semibold text-vault-950 transition hover:bg-vault-100 disabled:opacity-60",
                    r#type: "button",
                    disabled: pair_pin.read().is_none(),
                    onclick: copy_pin,
                    "Copiar PIN"
                }
            }
        }
    }
}

#[component]
fn SecretDetail(
    session: VaultSession,
    entry: SecretEntry,
    is_dark_mode: bool,
    on_error: EventHandler<String>,
    on_secret_moved: EventHandler<String>,
    on_vault_changed: EventHandler<VaultData>,
) -> Element {
    let initials = initials(&entry.title);
    let icon_kind = secret_icon_kind(&entry);
    let icon_class = icon_container_class(icon_kind, "h-12 w-12 shrink-0 rounded-full shadow-lg");
    let mut title = use_signal(|| entry.title.clone());
    let mut username = use_signal(|| entry.username.clone());
    let mut password = use_signal(|| entry.password.clone());
    let mut url = use_signal(|| entry.url.clone());
    let mut notes = use_signal(|| entry.notes.clone());
    let mut group = use_signal(|| entry.group.clone());
    let mut icon = use_signal(|| entry.icon.clone());
    let mut color = use_signal(|| normalize_secret_color(&entry.color));
    let mut custom_fields = use_signal(|| entry.custom_fields.clone());
    let mut favorite = use_signal(|| entry.favorite);
    let mut is_saving = use_signal(|| false);
    let mut is_password_visible = use_signal(|| false);
    let mut confirm_delete = use_signal(|| false);
    let mut is_generator_open = use_signal(|| false);
    let mut is_move_modal_open = use_signal(|| false);
    let mut status_message = use_signal(String::new);
    let eyebrow_class = if is_dark_mode {
        "text-sm font-medium text-brand-300"
    } else {
        "text-sm font-medium text-brand-600"
    };
    let detail_title_class = if is_dark_mode {
        "text-xl font-semibold tracking-tight text-white"
    } else {
        "text-xl font-semibold tracking-tight text-vault-950"
    };
    let detail_url_class = if is_dark_mode {
        "mt-1 text-sm text-vault-300"
    } else {
        "mt-1 text-sm text-vault-500"
    };
    let secondary_button_class = if is_dark_mode {
        "border border-white/10 px-4 py-2.5 text-sm font-medium text-vault-200 transition hover:bg-white/10 disabled:opacity-60"
    } else {
        "border border-vault-200 bg-white px-4 py-2.5 text-sm font-medium text-vault-700 transition hover:bg-vault-100 disabled:opacity-60"
    };
    let save_button_class = if is_dark_mode {
        "bg-white px-4 py-2.5 text-sm font-semibold text-vault-950 transition hover:bg-vault-100 disabled:opacity-60"
    } else {
        "bg-vault-950 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-vault-800 disabled:opacity-60"
    };
    let password_input_class = if is_dark_mode {
        "w-full border border-white/10 bg-vault-950/50 px-4 py-3 text-sm text-white placeholder:text-vault-500 focus:border-brand-400 focus:outline-none"
    } else {
        "w-full border border-vault-200 bg-white px-4 py-3 text-sm text-vault-950 placeholder:text-vault-400 focus:border-brand-500 focus:outline-none"
    };
    let generate_button_class = if is_dark_mode {
        "bg-brand-500 px-5 py-3 text-sm font-semibold text-white transition hover:bg-brand-400 sm:w-36"
    } else {
        "bg-brand-500 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-brand-500/20 transition hover:bg-brand-400 sm:w-36"
    };
    let eye_button_class = if is_dark_mode {
        "grid h-12 w-12 place-items-center border border-white/10 text-vault-50 transition hover:bg-white/10"
    } else {
        "grid h-12 w-12 place-items-center border border-vault-200 text-vault-700 transition hover:bg-vault-100"
    };
    let textarea_class = if is_dark_mode {
        "mt-2 h-24 w-full resize-none border border-white/10 bg-vault-950/50 px-4 py-3 text-sm text-white placeholder:text-vault-500 focus:border-brand-400 focus:outline-none"
    } else {
        "mt-2 h-24 w-full resize-none border border-vault-200 bg-white px-4 py-3 text-sm text-vault-950 placeholder:text-vault-400 focus:border-brand-500 focus:outline-none"
    };
    let favorite_class = if is_dark_mode {
        "flex items-center gap-3 border border-white/10 bg-vault-950/40 px-4 py-3 text-sm text-vault-300 sm:col-span-2"
    } else {
        "flex items-center gap-3 border border-vault-200 bg-vault-50 px-4 py-3 text-sm text-vault-700 sm:col-span-2"
    };
    let info_card_class = if is_dark_mode {
        "bg-mint-300/10 p-4 text-sm text-mint-300"
    } else {
        "bg-emerald-50 p-4 text-sm font-medium text-emerald-700"
    };
    let clipboard_card_class = if is_dark_mode {
        "bg-brand-500/10 p-4 text-sm text-brand-300"
    } else {
        "bg-blue-50 p-4 text-sm font-medium text-blue-700"
    };
    let delete_button_class = if is_dark_mode {
        "border border-red-400/30 bg-red-400/10 px-4 py-3 text-sm font-semibold text-red-200 transition hover:bg-red-400/20 disabled:opacity-60"
    } else {
        "border border-red-200 bg-red-50 px-4 py-3 text-sm font-semibold text-red-700 transition hover:bg-red-100 disabled:opacity-60"
    };
    let open_url_button_class = if is_dark_mode {
        "border border-white/10 bg-vault-950/40 px-4 py-3 text-sm font-semibold text-brand-300 transition hover:bg-white/10"
    } else {
        "border border-vault-200 bg-vault-50 px-4 py-3 text-sm font-semibold text-brand-600 transition hover:bg-vault-100"
    };
    let divider_class = if is_dark_mode {
        "border-white/10"
    } else {
        "border-vault-100"
    };
    let section_label_class =
        "text-[10px] font-semibold uppercase tracking-[0.22em] text-vault-400";

    let save_changes = {
        let entry_id = entry.id.clone();
        let session_path = session.path.clone();
        let session_master_password = session.master_password.clone();
        move |_| {
            let entry_id = entry_id.clone();
            let vault_path = session_path.clone();
            let master_password = session_master_password.clone();

            async move {
                if title.read().trim().is_empty() || password.read().is_empty() {
                    on_error.call("Título y contraseña son obligatorios.".to_string());
                    return;
                }

                is_saving.set(true);
                confirm_delete.set(false);
                status_message.set(String::new());
                on_error.call(String::new());

                let update = SecretEntryUpdateInput {
                    id: entry_id.clone(),
                    title: title.read().trim().to_string(),
                    username: username.read().trim().to_string(),
                    password: password.read().to_string(),
                    url: url.read().trim().to_string(),
                    notes: notes.read().trim().to_string(),
                    group: normalize_group_name(&group.read()),
                    icon: normalize_icon_value(&icon.read()),
                    color: normalize_secret_color(&color.read()),
                    custom_fields: normalize_custom_fields(custom_fields.read().clone()),
                    favorite: *favorite.read(),
                };

                match tauri_api::update_entry(&vault_path, &master_password, update).await {
                    Ok(vault) => {
                        status_message.set("Cambios guardados.".to_string());
                        on_vault_changed.call(vault);
                    }
                    Err(error) => on_error.call(error),
                }

                is_saving.set(false);
            }
        }
    };

    let delete_secret = {
        let entry_id = entry.id.clone();
        let session_path = session.path.clone();
        let session_master_password = session.master_password.clone();
        move |_| {
            let entry_id = entry_id.clone();
            let vault_path = session_path.clone();
            let master_password = session_master_password.clone();

            async move {
                if !*confirm_delete.read() {
                    confirm_delete.set(true);
                    status_message.set("Presiona Borrar otra vez para confirmar.".to_string());
                    return;
                }

                is_saving.set(true);
                status_message.set(String::new());
                on_error.call(String::new());

                match tauri_api::delete_entry(&vault_path, &master_password, &entry_id).await {
                    Ok(vault) => on_vault_changed.call(vault),
                    Err(error) => on_error.call(error),
                }

                is_saving.set(false);
            }
        }
    };

    let copy_password = move |_| async move {
        status_message.set(String::new());
        on_error.call(String::new());

        let value = password.read().clone();
        match tauri_api::copy_secret_to_clipboard(&value).await {
            Ok(()) => {
                status_message.set("Contraseña copiada. Se limpiará en 1 minuto.".to_string())
            }
            Err(error) => on_error.call(error),
        }
    };

    let open_link = move |_| async move {
        status_message.set(String::new());
        on_error.call(String::new());

        match tauri_api::open_url(&url.read()).await {
            Ok(()) => status_message.set("Enlace abierto en el navegador.".to_string()),
            Err(error) => on_error.call(error),
        }
    };

    rsx! {
        div { class: "flex h-full flex-col",

            // ── Header ────────────────────────────────────────────────────
            div { class: "flex min-w-0 items-center gap-3 border-l-[3px] pl-3",
                style: "border-left-color: {color.read()};",
                div { class: "{icon_class}",
                    SecretIcon { kind: icon_kind }
                    span { class: "absolute -bottom-0.5 -right-0.5 grid h-5 min-w-5 place-items-center rounded-full border border-vault-900 bg-white px-1 text-[10px] font-black text-vault-950", "{initials}" }
                }
                div { class: "min-w-0",
                    p { class: "{eyebrow_class} text-xs", "Credencial" }
                    h2 { class: "{detail_title_class} truncate", "{title}" }
                    p { class: "{detail_url_class} truncate text-xs", "{url}" }
                }
            }

            // ── Acciones ──────────────────────────────────────────────────
            div { class: "mt-4 grid w-full grid-cols-1 gap-2 sm:grid-cols-3",
                button {
                    class: "{secondary_button_class} w-full",
                    disabled: *is_saving.read(),
                    onclick: move |_| is_move_modal_open.set(true),
                    "Mover"
                }
                button {
                    class: "{secondary_button_class} w-full",
                    disabled: *is_saving.read(),
                    onclick: copy_password,
                    "Copiar contraseña"
                }
                button {
                    class: "{save_button_class} w-full",
                    disabled: *is_saving.read(),
                    onclick: save_changes,
                    if *is_saving.read() { "Guardando..." } else { "Guardar cambios" }
                }
            }

            if !status_message.read().is_empty() {
                p { class: "mt-4 border border-mint-300/20 bg-mint-300/10 px-4 py-2.5 text-sm text-mint-300", "{status_message}" }
            }

            // ── Sección: Identificación ───────────────────────────────────
            div { class: "mt-5 border-t {divider_class} pt-4",
                p { class: "{section_label_class}", "Identificación" }
                div { class: "mt-3 grid gap-3 sm:grid-cols-2",
                    FormInput { label: "Título", value: title.read().clone(), placeholder: "GitHub", is_dark_mode, on_change: move |value| title.set(value) }
                    FormInput { label: "Usuario", value: username.read().clone(), placeholder: "tu@correo.com", is_dark_mode, on_change: move |value| username.set(value) }
                    FormInput { label: "Grupo", value: group.read().clone(), placeholder: "Trabajo, Personal, Finanzas...", is_dark_mode, on_change: move |value| group.set(value) }
                    SecretColorInput { value: color.read().clone(), is_dark_mode, on_change: move |value| color.set(value) }
                    IconSelect { value: icon.read().clone(), is_dark_mode, on_change: move |value| icon.set(value) }
                    label { class: "{favorite_class}",
                        input {
                            class: "h-4 w-4 accent-brand-500",
                            r#type: "checkbox",
                            checked: *favorite.read(),
                            onchange: move |event| favorite.set(event.checked())
                        }
                        span { "Marcar como favorito" }
                    }
                }
            }

            // ── Sección: Acceso ───────────────────────────────────────────
            div { class: "mt-5 border-t {divider_class} pt-4",
                p { class: "{section_label_class}", "Acceso" }
                div { class: "mt-3 grid gap-3",
                    label { class: "block",
                        span { class: "text-xs font-medium text-vault-400", "Contraseña" }
                        div { class: "mt-2 flex flex-col gap-2 sm:flex-row",
                            input {
                                class: "{password_input_class}",
                                r#type: if *is_password_visible.read() { "text" } else { "password" },
                                value: "{password}",
                                placeholder: "Contraseña segura",
                                oninput: move |event| password.set(event.value())
                            }
                            button {
                                class: "{generate_button_class}",
                                onclick: move |_| is_generator_open.set(true),
                                "Generar"
                            }
                            button {
                                class: "{eye_button_class}",
                                title: if *is_password_visible.read() { "Ocultar contraseña" } else { "Mostrar contraseña" },
                                onclick: move |_| {
                                    let visible = *is_password_visible.read();
                                    is_password_visible.set(!visible);
                                },
                                EyeIcon { visible: *is_password_visible.read() }
                                span { class: "sr-only",
                                    if *is_password_visible.read() { "Ocultar contraseña" } else { "Mostrar contraseña" }
                                }
                            }
                        }
                    }
                    label { class: "block",
                        span { class: "text-xs font-medium text-vault-400", "URL" }
                        div { class: "mt-2 flex flex-col gap-2 sm:flex-row",
                            input {
                                class: "{password_input_class}",
                                value: "{url}",
                                placeholder: "https://example.com",
                                oninput: move |event| url.set(event.value())
                            }
                            button {
                                class: "{open_url_button_class}",
                                disabled: url.read().trim().is_empty(),
                                onclick: open_link,
                                "Abrir enlace"
                            }
                        }
                    }
                }
            }

            // ── Sección: Análisis ─────────────────────────────────────────
            div { class: "mt-5 border-t {divider_class} pt-4",
                p { class: "{section_label_class}", "Análisis" }
                div { class: "mt-3 grid gap-3",
                    PasswordStrengthMeter { password: password.read().clone(), is_dark_mode }
                    SecurityInsights {
                        risk: risk_summary(&entry, &session.entries),
                        is_dark_mode
                    }
                    CustomFieldsEditor {
                        fields: custom_fields.read().clone(),
                        is_dark_mode,
                        on_change: move |fields| custom_fields.set(fields)
                    }
                }
            }

            // ── Sección: Notas ────────────────────────────────────────────
            div { class: "mt-5 border-t {divider_class} pt-4",
                p { class: "{section_label_class}", "Notas" }
                div { class: "mt-3",
                    textarea {
                        class: "{textarea_class}",
                        value: "{notes}",
                        placeholder: "Pistas de recuperación, notas de rotación...",
                        oninput: move |event| notes.set(event.value())
                    }
                }
            }

            // ── Historial ─────────────────────────────────────────────────
            PasswordHistoryList {
                history: entry.password_history.clone(),
                is_dark_mode,
                on_error
            }
            EntryChangeHistoryList {
                history: entry.change_history.clone(),
                is_dark_mode
            }

            // ── Footer ────────────────────────────────────────────────────
            div { class: "mt-6 grid gap-2 sm:grid-cols-[1fr_1fr_auto]",
                div { class: "{info_card_class} text-xs", "Cifrado en reposo" }
                div { class: "{clipboard_card_class} text-xs", "Portapapeles con limpieza automática" }
                button {
                    class: "{delete_button_class}",
                    disabled: *is_saving.read(),
                    onclick: delete_secret,
                    if *confirm_delete.read() { "Confirmar borrado" } else { "Borrar" }
                }
            }
        }

        if *is_generator_open.read() {
            PasswordGeneratorModal {
                is_dark_mode,
                on_error,
                on_generated: move |generated| {
                    password.set(generated);
                    is_generator_open.set(false);
                },
                on_close: move |_| is_generator_open.set(false)
            }
        }

        if *is_move_modal_open.read() {
            MoveSecretModal {
                session: session.clone(),
                entry: entry.clone(),
                groups: session.groups.clone(),
                is_dark_mode,
                on_error,
                on_secret_moved,
                on_vault_changed,
                on_close: move |_| is_move_modal_open.set(false)
            }
        }
    }
}

#[component]
fn MoveSecretModal(
    session: VaultSession,
    entry: SecretEntry,
    groups: Vec<String>,
    is_dark_mode: bool,
    on_error: EventHandler<String>,
    on_secret_moved: EventHandler<String>,
    on_vault_changed: EventHandler<VaultData>,
    on_close: EventHandler<()>,
) -> Element {
    let mut selected_group = use_signal(String::new);
    let mut new_group = use_signal(String::new);
    let mut is_saving = use_signal(|| false);
    let select_class = if is_dark_mode {
        "mt-2 w-full border border-white/10 bg-vault-950/50 px-4 py-3 text-sm text-white focus:border-brand-400 focus:outline-none"
    } else {
        "mt-2 w-full border border-vault-200 bg-white px-4 py-3 text-sm text-vault-950 focus:border-brand-500 focus:outline-none"
    };

    let move_secret = {
        let vault_path = session.path.clone();
        let master_password = session.master_password.clone();
        let entry = entry.clone();
        move |_| {
            let vault_path = vault_path.clone();
            let master_password = master_password.clone();
            let entry = entry.clone();
            async move {
                let selected_group_value = selected_group.read().trim().to_string();
                let new_group_value = new_group.read().trim().to_string();

                if selected_group_value.is_empty() && new_group_value.is_empty() {
                    on_error.call("Elige una carpeta o escribe una nueva.".to_string());
                    return;
                }

                let target_group = if new_group_value.is_empty() {
                    normalize_group_name(&selected_group_value)
                } else {
                    normalize_group_name(&new_group_value)
                };

                is_saving.set(true);
                on_error.call(String::new());

                let update = SecretEntryUpdateInput {
                    id: entry.id.clone(),
                    title: entry.title.clone(),
                    username: entry.username.clone(),
                    password: entry.password.clone(),
                    url: entry.url.clone(),
                    notes: entry.notes.clone(),
                    group: target_group.clone(),
                    icon: entry.icon.clone(),
                    color: entry.color.clone(),
                    custom_fields: entry.custom_fields.clone(),
                    favorite: entry.favorite,
                };

                match tauri_api::update_entry(&vault_path, &master_password, update).await {
                    Ok(vault) => {
                        on_secret_moved.call(target_group);
                        on_vault_changed.call(vault);
                        on_close.call(());
                    }
                    Err(error) => on_error.call(error),
                }

                is_saving.set(false);
            }
        }
    };

    rsx! {
        ModalFrame {
            title: "Mover clave",
            subtitle: "Elige una carpeta existente o escribe una nueva.",
            is_dark_mode,
            on_close,

            div { class: "grid gap-4",
                label { class: "block",
                    span { class: "text-xs font-medium text-vault-400", "Carpeta existente" }
                    select {
                        class: "{select_class}",
                        value: "{selected_group.read()}",
                        onchange: move |event| selected_group.set(event.value()),
                        option { value: "", "Sin seleccionar" }
                        for group in groups {
                            option { value: "{group}", "{group}" }
                        }
                    }
                }

                FormInput {
                    label: "O crear nueva carpeta",
                    value: new_group.read().clone(),
                    placeholder: "Nueva carpeta...",
                    is_dark_mode,
                    on_change: move |value| new_group.set(value)
                }
            }

            div { class: "mt-6 flex flex-col-reverse justify-end gap-3 sm:flex-row",
                button {
                    class: "rounded-2xl border border-white/10 px-5 py-3 text-sm font-medium text-vault-200 transition hover:bg-white/10",
                    onclick: move |_| on_close.call(()),
                    "Cancelar"
                }
                button {
                    class: "rounded-2xl bg-brand-500 px-5 py-3 text-sm font-semibold text-white transition hover:bg-brand-400 disabled:opacity-60",
                    disabled: *is_saving.read(),
                    onclick: move_secret,
                    if *is_saving.read() { "Moviendo..." } else { "Mover clave" }
                }
            }
        }
    }
}

#[component]
fn CustomFieldsEditor(
    fields: Vec<CustomField>,
    is_dark_mode: bool,
    on_change: EventHandler<Vec<CustomField>>,
) -> Element {
    let fields_for_add = fields.clone();
    let title_class = if is_dark_mode {
        "text-sm font-semibold text-white"
    } else {
        "text-sm font-semibold text-vault-950"
    };
    let input_class = form_control_class(is_dark_mode);
    let button_class = if is_dark_mode {
        "border border-white/10 px-3 py-2 text-xs font-semibold text-brand-300 transition hover:bg-white/10"
    } else {
        "border border-vault-200 bg-white px-3 py-2 text-xs font-semibold text-brand-600 transition hover:bg-vault-100"
    };

    rsx! {
        div { class: "mt-3 grid gap-3 sm:col-span-2",
            div { class: "flex items-center justify-between gap-3",
                p { class: "{title_class}", "Campos personalizados" }
                button {
                    class: "{button_class}",
                    r#type: "button",
                    onclick: move |_| {
                        let mut next = fields_for_add.clone();
                        next.push(CustomField {
                            label: String::new(),
                            value: String::new(),
                        });
                        on_change.call(next);
                    },
                    "+ Campo"
                }
            }

            if fields.is_empty() {
                p { class: "text-sm text-vault-500", "Agrega datos extra como PIN, código de recuperación o número de cliente." }
            } else {
                div { class: "grid gap-2",
                    for (index, field) in fields.clone().into_iter().enumerate() {
                        {
                            let fields_for_label = fields.clone();
                            let fields_for_value = fields.clone();
                            let fields_for_remove = fields.clone();
                            rsx! {
                        div { key: "{index}", class: "grid gap-2 sm:grid-cols-[1fr_1fr_auto]",
                            input {
                                class: "{input_class}",
                                value: "{field.label}",
                                placeholder: "Etiqueta",
                                oninput: move |event| {
                                    let mut next = fields_for_label.clone();
                                    if let Some(item) = next.get_mut(index) {
                                        item.label = event.value();
                                    }
                                    on_change.call(next);
                                }
                            }
                            input {
                                class: "{input_class}",
                                value: "{field.value}",
                                placeholder: "Valor",
                                oninput: move |event| {
                                    let mut next = fields_for_value.clone();
                                    if let Some(item) = next.get_mut(index) {
                                        item.value = event.value();
                                    }
                                    on_change.call(next);
                                }
                            }
                            button {
                                class: "{button_class}",
                                r#type: "button",
                                onclick: move |_| {
                                    let mut next = fields_for_remove.clone();
                                    if index < next.len() {
                                        next.remove(index);
                                    }
                                    on_change.call(next);
                                },
                                "Quitar"
                            }
                        }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn PasswordStrengthMeter(password: String, is_dark_mode: bool) -> Element {
    let strength = password_strength(&password);
    let track_class = if is_dark_mode {
        "h-2 overflow-hidden bg-white/10"
    } else {
        "h-2 overflow-hidden bg-vault-200"
    };
    let bar_class = match strength.level {
        0 | 1 => "h-full bg-red-500",
        2 => "h-full bg-amber-500",
        3 => "h-full bg-blue-500",
        _ => "h-full bg-emerald-500",
    };
    let label_class = if is_dark_mode {
        "text-xs text-vault-400"
    } else {
        "text-xs text-vault-500"
    };

    rsx! {
        div { class: "mt-3 grid gap-2",
            div { class: "flex items-center justify-between gap-3",
                span { class: "{label_class}", "Fuerza de contraseña" }
                span { class: "{label_class}", "{strength.label}" }
            }
            div { class: "{track_class}",
                div {
                    class: "{bar_class}",
                    style: "width: {strength.percent}%;"
                }
            }
            if !strength.hint.is_empty() {
                p { class: "{label_class}", "{strength.hint}" }
            }
        }
    }
}

#[component]
fn SecurityInsights(risk: RiskSummary, is_dark_mode: bool) -> Element {
    let shell_class = if is_dark_mode {
        "border border-white/10 bg-white/[0.03] p-4"
    } else {
        "border border-vault-200 bg-vault-50 p-4"
    };
    let title_class = if is_dark_mode {
        "text-sm font-semibold text-white"
    } else {
        "text-sm font-semibold text-vault-950"
    };
    let issues = [
        (risk.weak, "Contraseña débil o media"),
        (risk.reused, "Contraseña reutilizada en otra entrada"),
        (
            risk.similar,
            "Contraseña similar a otra entrada (riesgo por variación mínima)",
        ),
        (
            risk.duplicated_domain,
            "Dominio repetido en múltiples entradas",
        ),
        (risk.exposed, "Patrones comunes de contraseña expuesta"),
        (risk.old_password, "Contraseña sin rotación reciente"),
        (risk.missing_username, "Falta usuario"),
        (risk.missing_url, "Falta URL"),
        (risk.has_history, "Tiene historial de contraseñas"),
    ];
    let has_issues = issues.iter().any(|(active, _)| *active);

    rsx! {
        div { class: "{shell_class}",
            p { class: "{title_class}", "Análisis de seguridad" }
            if has_issues {
                div { class: "mt-3 flex flex-wrap gap-2",
                    for (active, label) in issues {
                        if active {
                            span { class: "rounded-full bg-amber-100 px-2.5 py-1 text-xs font-medium text-amber-700", "{label}" }
                        }
                    }
                }
            } else {
                p { class: "mt-2 text-sm text-vault-500", "Sin riesgos básicos detectados." }
            }
        }
    }
}

#[component]
fn PasswordHistoryList(
    history: Vec<PasswordHistoryEntry>,
    is_dark_mode: bool,
    on_error: EventHandler<String>,
) -> Element {
    let mut copied_index = use_signal(|| None::<usize>);
    let shell_class = if is_dark_mode {
        "mt-6 border border-white/10 bg-white/[0.03] p-4"
    } else {
        "mt-6 border border-vault-200 bg-vault-50 p-4"
    };
    let title_class = if is_dark_mode {
        "text-sm font-semibold text-white"
    } else {
        "text-sm font-semibold text-vault-950"
    };
    let row_class = if is_dark_mode {
        "flex items-center justify-between gap-3 border border-white/10 bg-vault-950/40 px-4 py-3"
    } else {
        "flex items-center justify-between gap-3 border border-vault-200 bg-white px-4 py-3"
    };
    let copy_class = if is_dark_mode {
        "shrink-0 border border-white/10 px-3 py-2 text-xs font-semibold text-brand-300 transition hover:bg-white/10"
    } else {
        "shrink-0 border border-vault-200 bg-vault-50 px-3 py-2 text-xs font-semibold text-brand-600 transition hover:bg-vault-100"
    };

    rsx! {
        div { class: "{shell_class}",
            div { class: "flex items-center justify-between gap-3",
                p { class: "{title_class}", "Historial de contraseñas" }
                span { class: "text-xs text-vault-500", "{history.len()} guardadas" }
            }

            if history.is_empty() {
                p { class: "mt-3 text-sm text-vault-500", "Cuando cambies esta contraseña, la anterior aparecerá aquí." }
            } else {
                div { class: "mt-3 grid gap-2",
                    for (index, item) in history.into_iter().enumerate() {
                        div { key: "{index}", class: "{row_class}",
                            div { class: "min-w-0",
                                p { class: "font-mono text-sm text-vault-400", "••••••••••••••••" }
                                p { class: "mt-1 text-xs text-vault-500", "{format_history_timestamp(item.changed_at)}" }
                            }
                            button {
                                class: "{copy_class}",
                                onclick: move |_| {
                                    let password = item.password.clone();
                                    async move {
                                        on_error.call(String::new());
                                        match tauri_api::copy_secret_to_clipboard(&password).await {
                                            Ok(()) => copied_index.set(Some(index)),
                                            Err(error) => on_error.call(error),
                                        }
                                    }
                                },
                                if copied_index.read().is_some_and(|copied| copied == index) {
                                    "Copiada"
                                } else {
                                    "Copiar"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn EntryChangeHistoryList(history: Vec<EntryChangeRecord>, is_dark_mode: bool) -> Element {
    let shell_class = if is_dark_mode {
        "mt-6 border border-white/10 bg-white/[0.03] p-4"
    } else {
        "mt-6 border border-vault-200 bg-vault-50 p-4"
    };
    let title_class = if is_dark_mode {
        "text-sm font-semibold text-white"
    } else {
        "text-sm font-semibold text-vault-950"
    };
    let row_class = if is_dark_mode {
        "border border-white/10 bg-vault-950/40 px-4 py-3"
    } else {
        "border border-vault-200 bg-white px-4 py-3"
    };

    rsx! {
        div { class: "{shell_class}",
            div { class: "flex items-center justify-between gap-3",
                p { class: "{title_class}", "Historial de cambios" }
                span { class: "text-xs text-vault-500", "{history.len()} eventos" }
            }
            if history.is_empty() {
                p { class: "mt-3 text-sm text-vault-500", "Los cambios de esta entrada aparecerán aquí." }
            } else {
                div { class: "mt-3 grid gap-2",
                    for (index, item) in history.into_iter().enumerate() {
                        div { key: "{index}", class: "{row_class}",
                            p { class: "text-sm font-medium text-vault-100", "{item.action}" }
                            p { class: "mt-1 text-sm text-vault-400", "{item.details}" }
                            p { class: "mt-1 text-xs text-vault-500", "{format_history_timestamp(item.changed_at)}" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn PasswordGeneratorModal(
    is_dark_mode: bool,
    on_error: EventHandler<String>,
    on_generated: EventHandler<String>,
    on_close: EventHandler<()>,
) -> Element {
    let mut length = use_signal(|| "24".to_string());
    let mut include_uppercase = use_signal(|| true);
    let mut include_lowercase = use_signal(|| true);
    let mut include_numbers = use_signal(|| true);
    let mut include_symbols = use_signal(|| true);
    let mut generated_password = use_signal(String::new);
    let mut modal_error = use_signal(String::new);
    let mut is_generating = use_signal(|| false);
    let card_class = if is_dark_mode {
        "border border-white/10 bg-vault-950/40 p-4"
    } else {
        "border border-vault-200 bg-white p-4"
    };
    let label_class = if is_dark_mode {
        "text-sm font-medium text-vault-300"
    } else {
        "text-sm font-medium text-vault-600"
    };
    let number_input_class = if is_dark_mode {
        "mt-2 w-full border border-white/10 bg-vault-950/60 px-4 py-3 text-sm text-white focus:border-brand-400 focus:outline-none"
    } else {
        "mt-2 w-full border border-vault-200 bg-white px-4 py-3 text-sm text-vault-950 focus:border-brand-500 focus:outline-none"
    };
    let generated_class = if is_dark_mode {
        "mt-3 break-all font-mono text-sm leading-6 text-white"
    } else {
        "mt-3 break-all font-mono text-sm leading-6 text-vault-950"
    };
    let error_class = if is_dark_mode {
        "border border-red-400/20 bg-red-400/10 px-4 py-3 text-sm text-red-200"
    } else {
        "border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"
    };

    let generate = move |_| async move {
        let Ok(length) = length.read().parse::<usize>() else {
            modal_error.set("La longitud debe ser un número válido.".to_string());
            return;
        };

        is_generating.set(true);
        modal_error.set(String::new());
        on_error.call(String::new());

        match tauri_api::generate_password(Some(PasswordGenerationOptions {
            length,
            include_uppercase: *include_uppercase.read(),
            include_lowercase: *include_lowercase.read(),
            include_numbers: *include_numbers.read(),
            include_symbols: *include_symbols.read(),
        }))
        .await
        {
            Ok(generated) => generated_password.set(generated.password),
            Err(error) => modal_error.set(error),
        }

        is_generating.set(false);
    };

    rsx! {
        ModalFrame {
            title: "Generador de contraseñas",
            subtitle: "Personaliza la contraseña antes de usarla en el secreto.",
            is_dark_mode,
            on_close,

            div { class: "grid gap-5",
                div { class: "{card_class}",
                    label { class: "block",
                        span { class: "{label_class}", "Número de caracteres" }
                        input {
                            class: "{number_input_class}",
                            r#type: "number",
                            min: "12",
                            max: "128",
                            value: "{length}",
                            oninput: move |event| {
                                length.set(event.value());
                                modal_error.set(String::new());
                            }
                        }
                    }
                    p { class: "mt-2 text-xs text-vault-500", "Rango permitido: 12 a 128 caracteres." }
                }

                if !modal_error.read().is_empty() {
                    p { class: "{error_class}", "{modal_error}" }
                }

                div { class: "grid gap-3 sm:grid-cols-2",
                    GeneratorOption {
                        label: "Minúsculas",
                        description: "a-z",
                        checked: *include_lowercase.read(),
                        on_change: move |value| include_lowercase.set(value)
                    }
                    GeneratorOption {
                        label: "Mayúsculas",
                        description: "A-Z",
                        checked: *include_uppercase.read(),
                        on_change: move |value| include_uppercase.set(value)
                    }
                    GeneratorOption {
                        label: "Números",
                        description: "2-9",
                        checked: *include_numbers.read(),
                        on_change: move |value| include_numbers.set(value)
                    }
                    GeneratorOption {
                        label: "Caracteres especiales",
                        description: "!@#$%^&*",
                        checked: *include_symbols.read(),
                        on_change: move |value| include_symbols.set(value)
                    }
                }

                div { class: "{card_class}",
                    p { class: "text-xs font-semibold uppercase tracking-[0.22em] text-vault-500", "Resultado" }
                    if generated_password.read().is_empty() {
                        p { class: "mt-3 text-sm text-vault-400", "Genera una contraseña para verla aquí." }
                    } else {
                        p { class: "{generated_class}", "{generated_password}" }
                        PasswordStrengthMeter { password: generated_password.read().clone(), is_dark_mode }
                    }
                }

                div { class: "flex flex-col-reverse justify-end gap-3 sm:flex-row",
                    button {
                        class: "rounded-2xl border border-white/10 px-5 py-3 text-sm font-medium text-vault-200 transition hover:bg-white/10",
                        onclick: move |_| on_close.call(()),
                        "Cancelar"
                    }
                    button {
                        class: "rounded-2xl border border-brand-400/30 bg-brand-500/10 px-5 py-3 text-sm font-semibold text-brand-300 transition hover:bg-brand-500/20 disabled:opacity-60",
                        disabled: *is_generating.read(),
                        onclick: generate,
                        if *is_generating.read() { "Generando..." } else { "Generar" }
                    }
                    button {
                        class: "rounded-2xl bg-white px-5 py-3 text-sm font-semibold text-vault-950 transition hover:bg-vault-100 disabled:opacity-60",
                        disabled: generated_password.read().is_empty(),
                        onclick: move |_| on_generated.call(generated_password.read().clone()),
                        "Usar contraseña"
                    }
                }
            }
        }
    }
}

#[component]
fn GeneratorOption(
    label: &'static str,
    description: &'static str,
    checked: bool,
    on_change: EventHandler<bool>,
) -> Element {
    rsx! {
        label { class: "flex items-center gap-3 rounded-2xl border border-white/10 bg-vault-950/40 p-4 text-sm text-vault-300",
            input {
                class: "h-4 w-4 accent-brand-500",
                r#type: "checkbox",
                checked,
                onchange: move |event| on_change.call(event.checked())
            }
            span { class: "min-w-0",
                span { class: "block font-medium text-white", "{label}" }
                span { class: "block text-xs text-vault-500", "{description}" }
            }
        }
    }
}

#[component]
fn FormInput(
    label: &'static str,
    value: String,
    placeholder: &'static str,
    is_dark_mode: bool,
    on_change: EventHandler<String>,
) -> Element {
    let label_class = form_label_class();
    let input_class = form_control_class(is_dark_mode);

    rsx! {
        label { class: "block",
            span { class: "{label_class}", "{label}" }
            input {
                class: "{input_class}",
                value: "{value}",
                placeholder: "{placeholder}",
                oninput: move |event| on_change.call(event.value())
            }
        }
    }
}

#[component]
fn PasswordInput(
    label: &'static str,
    value: String,
    placeholder: &'static str,
    is_dark_mode: bool,
    on_change: EventHandler<String>,
) -> Element {
    let label_class = form_label_class();
    let input_class = form_control_class(is_dark_mode);

    rsx! {
        label { class: "block",
            span { class: "{label_class}", "{label}" }
            input {
                class: "{input_class}",
                r#type: "password",
                value: "{value}",
                placeholder: "{placeholder}",
                oninput: move |event| on_change.call(event.value())
            }
        }
    }
}

#[component]
fn SecretColorInput(value: String, is_dark_mode: bool, on_change: EventHandler<String>) -> Element {
    let label_class = form_label_class();
    let text_input_class = form_control_class(is_dark_mode);
    let color = normalize_secret_color(&value);
    let picker_shell_class = if is_dark_mode {
        "mt-2 flex items-center gap-3 border border-white/10 bg-vault-950/50 px-3 py-2"
    } else {
        "mt-2 flex items-center gap-3 border border-vault-200 bg-white px-3 py-2"
    };

    rsx! {
        label { class: "block",
            span { class: "{label_class}", "Color" }
            div { class: "{picker_shell_class}",
                input {
                    r#type: "color",
                    value: "{color}",
                    class: "h-9 w-12 cursor-pointer border-0 bg-transparent p-0",
                    oninput: move |event| on_change.call(event.value())
                }
                input {
                    class: "{text_input_class} mt-0",
                    value: "{color}",
                    placeholder: "#6366F1",
                    oninput: move |event| on_change.call(event.value())
                }
            }
        }
    }
}

#[component]
fn IconSelect(value: String, is_dark_mode: bool, on_change: EventHandler<String>) -> Element {
    let selected = normalize_icon_value(&value).to_lowercase();
    let label_class = form_label_class();
    let hint_class = if is_dark_mode {
        "text-xs text-vault-500"
    } else {
        "text-xs text-vault-400"
    };

    rsx! {
        div { class: "block sm:col-span-2",
            div { class: "flex items-center justify-between gap-3",
                span { class: "{label_class}", "Icono" }
                span { class: "{hint_class}", "Elige visualmente" }
            }
            div { class: "mt-2 grid grid-cols-6 gap-2 sm:grid-cols-11",
                for option in ICON_OPTIONS {
                    button {
                        key: "{option.value}",
                        class: icon_option_class(option.kind, selected == option.value),
                        r#type: "button",
                        title: "{option.label}",
                        onclick: move |_| on_change.call(option.value.to_string()),
                        SecretIcon { kind: option.kind }
                        span { class: "sr-only", "{option.label}" }
                    }
                }
            }
        }
    }
}

#[component]
fn EyeIcon(visible: bool) -> Element {
    rsx! {
        svg {
            class: "h-5 w-5",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            stroke_width: "1.8",
            stroke_linecap: "round",
            stroke_linejoin: "round",
            if visible {
                path { d: "M2.5 12s3.5-6.5 9.5-6.5S21.5 12 21.5 12s-3.5 6.5-9.5 6.5S2.5 12 2.5 12Z" }
                circle { cx: "12", cy: "12", r: "3" }
            } else {
                path { d: "M3 3l18 18" }
                path { d: "M10.6 10.6a3 3 0 0 0 2.8 2.8" }
                path { d: "M9.5 5.8A9.3 9.3 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a18 18 0 0 1-2.1 2.9" }
                path { d: "M6.4 7.4C3.9 9 2.5 12 2.5 12s3.5 6.5 9.5 6.5a9.9 9.9 0 0 0 4.1-.9" }
            }
        }
    }
}

#[component]
fn SecretIcon(kind: SecretIconKind) -> Element {
    rsx! {
        svg {
            class: "h-6 w-6",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            stroke_width: "1.8",
            stroke_linecap: "round",
            stroke_linejoin: "round",
            match kind {
                SecretIconKind::Amazon => rsx! {
                    path { d: "M6 8h12l-1.2 8H7.2L6 8Z" }
                    path { d: "M8 8a4 4 0 0 1 8 0" }
                    path { d: "M7 19c3 1.8 7 1.8 10 0" }
                    path { d: "M16 18.2l2 .8-1.1 1.8" }
                },
                SecretIconKind::Apple => rsx! {
                    path { d: "M15.5 4.5c-.8.6-1.5 1.6-1.4 2.6 1-.1 2-.7 2.6-1.5.5-.7.8-1.6.7-2.4-.7 0-1.4.4-1.9 1.3Z" }
                    path { d: "M18.5 16.7c-.5 1.2-.8 1.7-1.5 2.8-1 1.4-2.3 1.3-3 1-1.1-.4-1.9-.4-3 0-.8.3-2.1.4-3-1-1.7-2.4-3-6.7-1.3-9.4 1-1.6 2.5-2.5 4.1-2.5 1 0 1.9.6 2.5.6.6 0 1.7-.7 2.9-.6.5 0 2 .2 3 1.6-2.6 1.5-2.2 5.3.3 6.5Z" }
                },
                SecretIconKind::Auto => rsx! {
                    path { d: "M12 3l1.2 4.2L17 9l-3.8 1.8L12 15l-1.2-4.2L7 9l3.8-1.8L12 3Z" }
                    path { d: "M5 14l.7 2.3L8 17l-2.3.7L5 20l-.7-2.3L2 17l2.3-.7L5 14Z" }
                    path { d: "M19 14l.7 2.3L22 17l-2.3.7L19 20l-.7-2.3L16 17l2.3-.7L19 14Z" }
                },
                SecretIconKind::Bank => rsx! {
                    path { d: "M3 10h18" }
                    path { d: "M5 10l7-5 7 5" }
                    path { d: "M6 10v8" }
                    path { d: "M10 10v8" }
                    path { d: "M14 10v8" }
                    path { d: "M18 10v8" }
                    path { d: "M4 18h16" }
                },
                SecretIconKind::Cart => rsx! {
                    path { d: "M4 5h2l2 11h10l2-7H8" }
                    circle { cx: "10", cy: "20", r: "1.5" }
                    circle { cx: "17", cy: "20", r: "1.5" }
                },
                SecretIconKind::Cloud => rsx! {
                    path { d: "M7 18h10a4 4 0 0 0 .7-7.9A6 6 0 0 0 6.3 8.5 4.5 4.5 0 0 0 7 18Z" }
                },
                SecretIconKind::Code => rsx! {
                    path { d: "M8 9l-4 3 4 3" }
                    path { d: "M16 9l4 3-4 3" }
                    path { d: "M14 5l-4 14" }
                },
                SecretIconKind::Facebook => rsx! {
                    path { d: "M14 8h2V4h-3a5 5 0 0 0-5 5v3H5v4h3v5h4v-5h3l1-4h-4V9a1 1 0 0 1 1-1h1Z" }
                },
                SecretIconKind::Game => rsx! {
                    path { d: "M7 15h10l2 3a2 2 0 0 0 3-2l-1-6a4 4 0 0 0-4-3H7a4 4 0 0 0-4 3l-1 6a2 2 0 0 0 3 2l2-3Z" }
                    path { d: "M8 10v4" }
                    path { d: "M6 12h4" }
                    path { d: "M16 11h.01" }
                    path { d: "M18 14h.01" }
                },
                SecretIconKind::Github => rsx! {
                    path { d: "M9 19c-4 1.2-4-2-5-2.5" }
                    path { d: "M15 21v-3.5c0-1 .3-1.7.8-2.2 2.7-.3 5.7-1.4 5.7-6A4.6 4.6 0 0 0 20 5.8 4.2 4.2 0 0 0 19.9 2s-1.2-.4-3.9 1.5a13.4 13.4 0 0 0-7 0C6.3 1.6 5.1 2 5.1 2A4.2 4.2 0 0 0 5 5.8a4.6 4.6 0 0 0-1.5 3.5c0 4.6 3 5.7 5.7 6 .5.5.8 1.2.8 2.2V21" }
                },
                SecretIconKind::Globe => rsx! {
                    circle { cx: "12", cy: "12", r: "9" }
                    path { d: "M3 12h18" }
                    path { d: "M12 3a14 14 0 0 1 0 18" }
                    path { d: "M12 3a14 14 0 0 0 0 18" }
                },
                SecretIconKind::Google => rsx! {
                    path { d: "M20.5 12.2c0-.7-.1-1.3-.2-1.9H12v3.6h4.7a4 4 0 0 1-1.7 2.6v2.2h2.8a8.5 8.5 0 0 0 2.7-6.5Z" }
                    path { d: "M12 21a8.8 8.8 0 0 0 5.8-2.1L15 16.7a5.2 5.2 0 0 1-7.8-2.8H4.3v2.3A9 9 0 0 0 12 21Z" }
                    path { d: "M7.2 13.9a5.4 5.4 0 0 1 0-3.8V7.8H4.3a9 9 0 0 0 0 8.4l2.9-2.3Z" }
                    path { d: "M12 6.7c1.4 0 2.6.5 3.6 1.4l2.5-2.5A8.8 8.8 0 0 0 12 3a9 9 0 0 0-7.7 4.8l2.9 2.3A5.3 5.3 0 0 1 12 6.7Z" }
                },
                SecretIconKind::Instagram => rsx! {
                    rect { x: "4", y: "4", width: "16", height: "16", rx: "5" }
                    circle { cx: "12", cy: "12", r: "3.5" }
                    path { d: "M16.8 7.2h.01" }
                },
                SecretIconKind::Key => rsx! {
                    circle { cx: "8", cy: "15", r: "3" }
                    path { d: "M10.2 12.8 20 3" }
                    path { d: "M15 8l2 2" }
                    path { d: "M18 5l2 2" }
                },
                SecretIconKind::Mail => rsx! {
                    path { d: "M4 6h16v12H4z" }
                    path { d: "m4 7 8 6 8-6" }
                },
                SecretIconKind::Media => rsx! {
                    rect { x: "4", y: "5", width: "16", height: "14", rx: "2" }
                    path { d: "m10 9 6 3-6 3V9Z" }
                },
                SecretIconKind::Microsoft => rsx! {
                    rect { x: "4", y: "4", width: "7", height: "7", fill: "currentColor", stroke: "none" }
                    rect { x: "13", y: "4", width: "7", height: "7", fill: "currentColor", stroke: "none" }
                    rect { x: "4", y: "13", width: "7", height: "7", fill: "currentColor", stroke: "none" }
                    rect { x: "13", y: "13", width: "7", height: "7", fill: "currentColor", stroke: "none" }
                },
                SecretIconKind::Netflix => rsx! {
                    path { d: "M7 20V4h3l4 10V4h3v16h-3L10 10v10H7Z" }
                },
                SecretIconKind::Server => rsx! {
                    rect { x: "4", y: "4", width: "16", height: "6", rx: "2" }
                    rect { x: "4", y: "14", width: "16", height: "6", rx: "2" }
                    path { d: "M8 7h.01" }
                    path { d: "M8 17h.01" }
                },
                SecretIconKind::Social => rsx! {
                    circle { cx: "9", cy: "8", r: "3" }
                    path { d: "M3.5 19a5.5 5.5 0 0 1 11 0" }
                    path { d: "M16 11a3 3 0 1 0 0-6" }
                    path { d: "M17.5 19a5.5 5.5 0 0 0-2.5-4.6" }
                },
                SecretIconKind::Spotify => rsx! {
                    circle { cx: "12", cy: "12", r: "9" }
                    path { d: "M8 10c3-.8 6-.5 8.5 1" }
                    path { d: "M8.5 13c2.4-.6 4.8-.4 7 .8" }
                    path { d: "M9 16c1.8-.4 3.7-.3 5.4.5" }
                },
                SecretIconKind::Youtube => rsx! {
                    rect { x: "3", y: "6.5", width: "18", height: "11", rx: "4" }
                    path { d: "m10.5 10 4 2-4 2v-4Z", fill: "currentColor", stroke: "none" }
                },
            }
        }
    }
}

#[derive(Clone)]
struct GroupCount {
    name: String,
    count: usize,
}

fn group_counts(saved_groups: &[String], entries: &[SecretEntry]) -> Vec<GroupCount> {
    let mut groups = Vec::<GroupCount>::new();

    for group in saved_groups {
        let group = normalize_group_name(group);
        if !groups.iter().any(|item| item.name == group) {
            groups.push(GroupCount {
                name: group,
                count: 0,
            });
        }
    }

    for entry in entries {
        let group = normalize_group_name(&entry.group);

        if let Some(existing) = groups.iter_mut().find(|item| item.name == group) {
            existing.count += 1;
        } else {
            groups.push(GroupCount {
                name: group,
                count: 1,
            });
        }
    }

    groups.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    if groups.is_empty() {
        groups.push(GroupCount {
            name: DEFAULT_GROUP.to_string(),
            count: 0,
        });
    }

    groups
}

fn filter_matches(entry: &SecretEntry, selected_group: &str, entries: &[SecretEntry]) -> bool {
    match selected_group {
        ALL_GROUPS => true,
        FAVORITES_GROUP => entry.favorite,
        WEAK_GROUP => password_strength(&entry.password).level <= 2,
        REUSED_GROUP => risk_summary(entry, entries).reused,
        RISKY_GROUP => entry_has_risk(entry, entries),
        HISTORY_GROUP => !entry.password_history.is_empty(),
        group => normalize_group_name(&entry.group) == group,
    }
}

fn is_folder_filter(selected_group: &str) -> bool {
    !matches!(
        selected_group,
        ALL_GROUPS | FAVORITES_GROUP | WEAK_GROUP | REUSED_GROUP | RISKY_GROUP | HISTORY_GROUP
    )
}

fn normalize_group_name(group: &str) -> String {
    let group = group.trim();

    if group.is_empty() {
        DEFAULT_GROUP.to_string()
    } else {
        group.to_string()
    }
}

fn normalize_icon_value(icon: &str) -> String {
    let icon = icon.trim();

    if icon.is_empty() {
        DEFAULT_ICON.to_string()
    } else {
        icon.to_string()
    }
}

fn normalize_secret_color(color: &str) -> String {
    let color = color.trim();
    if color.is_empty() {
        return DEFAULT_SECRET_COLOR.to_string();
    }
    let normalized = if color.starts_with('#') {
        color.to_string()
    } else {
        format!("#{color}")
    };
    let hex = normalized.trim_start_matches('#');
    let valid = hex.len() == 6 && hex.chars().all(|ch| ch.is_ascii_hexdigit());
    if valid {
        format!("#{}", hex.to_uppercase())
    } else {
        DEFAULT_SECRET_COLOR.to_string()
    }
}

fn normalize_custom_fields(fields: Vec<CustomField>) -> Vec<CustomField> {
    fields
        .into_iter()
        .filter_map(|field| {
            let label = field.label.trim().to_string();
            let value = field.value.trim().to_string();

            if label.is_empty() && value.is_empty() {
                None
            } else {
                Some(CustomField { label, value })
            }
        })
        .collect()
}

fn form_label_class() -> &'static str {
    "text-xs font-medium text-vault-400"
}

fn form_control_class(is_dark_mode: bool) -> &'static str {
    if is_dark_mode {
        "mt-2 w-full border border-white/10 bg-vault-950/50 px-4 py-3 text-sm text-white placeholder:text-vault-500 focus:border-brand-400 focus:outline-none"
    } else {
        "mt-2 w-full border border-vault-200 bg-white px-4 py-3 text-sm text-vault-950 placeholder:text-vault-400 focus:border-brand-500 focus:outline-none"
    }
}

fn load_theme_preference() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|window| window.local_storage().ok().flatten())
            .and_then(|storage| storage.get_item(THEME_KEY).ok().flatten())
            .map(|theme| theme != "light")
            .unwrap_or(true)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        true
    }
}

fn save_theme_preference(is_dark_mode: bool) {
    #[cfg(target_arch = "wasm32")]
    if let Some(storage) =
        web_sys::window().and_then(|window| window.local_storage().ok().flatten())
    {
        let _ = storage.set_item(THEME_KEY, if is_dark_mode { "dark" } else { "light" });
    }

    #[cfg(not(target_arch = "wasm32"))]
    let _ = is_dark_mode;
}

fn load_last_vault_path() -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|window| window.local_storage().ok().flatten())
            .and_then(|storage| storage.get_item(LAST_VAULT_PATH_KEY).ok().flatten())
            .filter(|path| !path.trim().is_empty())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

fn save_last_vault_path(path: &str) {
    if path.trim().is_empty() {
        return;
    }

    #[cfg(target_arch = "wasm32")]
    if let Some(storage) =
        web_sys::window().and_then(|window| window.local_storage().ok().flatten())
    {
        let _ = storage.set_item(LAST_VAULT_PATH_KEY, path);
    }

    #[cfg(not(target_arch = "wasm32"))]
    let _ = path;
}

fn selected_entry(session: &VaultSession, filtered_entries: &[SecretEntry]) -> Option<SecretEntry> {
    session
        .selected_id
        .as_ref()
        .and_then(|id| filtered_entries.iter().find(|entry| &entry.id == id))
        .cloned()
        .or_else(|| filtered_entries.first().cloned())
}

fn secret_matches(entry: &SecretEntry, search: &str) -> bool {
    let search = search.trim().to_lowercase();
    if search.is_empty() {
        return true;
    }

    entry.title.to_lowercase().contains(&search)
        || entry.username.to_lowercase().contains(&search)
        || entry.url.to_lowercase().contains(&search)
}

fn icon_container_class(kind: SecretIconKind, size_class: &str) -> String {
    format!(
        "relative grid place-items-center text-white {} {}",
        size_class,
        icon_background_class(kind)
    )
}

fn icon_option_class(kind: SecretIconKind, active: bool) -> String {
    if active {
        format!(
            "grid h-11 w-11 place-items-center rounded-full border border-white/70 text-white shadow-lg ring-2 ring-brand-300/50 {}",
            icon_background_class(kind)
        )
    } else {
        format!(
            "grid h-11 w-11 place-items-center rounded-full border border-white/10 text-white/90 transition hover:scale-105 hover:border-white/30 {}",
            icon_background_class(kind)
        )
    }
}

fn icon_background_class(kind: SecretIconKind) -> &'static str {
    match kind {
        SecretIconKind::Amazon => {
            "bg-gradient-to-br from-orange-400 to-amber-600 shadow-orange-500/20"
        }
        SecretIconKind::Apple => "bg-gradient-to-br from-zinc-500 to-zinc-900 shadow-zinc-500/20",
        SecretIconKind::Auto => {
            "bg-gradient-to-br from-violet-500 to-fuchsia-500 shadow-violet-500/20"
        }
        SecretIconKind::Bank => "bg-gradient-to-br from-blue-500 to-indigo-700 shadow-blue-500/20",
        SecretIconKind::Cart => {
            "bg-gradient-to-br from-amber-400 to-orange-600 shadow-amber-500/20"
        }
        SecretIconKind::Cloud => "bg-gradient-to-br from-sky-400 to-cyan-600 shadow-sky-500/20",
        SecretIconKind::Code => "bg-gradient-to-br from-slate-600 to-slate-950 shadow-slate-500/20",
        SecretIconKind::Facebook => {
            "bg-gradient-to-br from-blue-500 to-blue-700 shadow-blue-500/20"
        }
        SecretIconKind::Game => {
            "bg-gradient-to-br from-purple-500 to-indigo-700 shadow-purple-500/20"
        }
        SecretIconKind::Github => {
            "bg-gradient-to-br from-neutral-700 to-black shadow-neutral-500/20"
        }
        SecretIconKind::Globe => "bg-gradient-to-br from-brand-500 to-mint-500 shadow-brand-500/20",
        SecretIconKind::Google => {
            "bg-gradient-to-br from-blue-500 via-emerald-500 to-amber-400 shadow-blue-500/20"
        }
        SecretIconKind::Instagram => {
            "bg-gradient-to-br from-fuchsia-500 via-rose-500 to-amber-400 shadow-rose-500/20"
        }
        SecretIconKind::Key => "bg-gradient-to-br from-vault-500 to-vault-900 shadow-vault-500/20",
        SecretIconKind::Mail => "bg-gradient-to-br from-cyan-500 to-blue-700 shadow-cyan-500/20",
        SecretIconKind::Media => "bg-gradient-to-br from-rose-500 to-pink-700 shadow-rose-500/20",
        SecretIconKind::Microsoft => {
            "bg-gradient-to-br from-emerald-500 via-blue-500 to-orange-500 shadow-blue-500/20"
        }
        SecretIconKind::Netflix => "bg-gradient-to-br from-red-600 to-red-950 shadow-red-500/20",
        SecretIconKind::Server => {
            "bg-gradient-to-br from-emerald-500 to-teal-800 shadow-emerald-500/20"
        }
        SecretIconKind::Social => {
            "bg-gradient-to-br from-pink-500 to-purple-700 shadow-pink-500/20"
        }
        SecretIconKind::Spotify => {
            "bg-gradient-to-br from-green-400 to-green-700 shadow-green-500/20"
        }
        SecretIconKind::Youtube => "bg-gradient-to-br from-red-500 to-red-700 shadow-red-500/20",
    }
}

fn secret_icon_kind(entry: &SecretEntry) -> SecretIconKind {
    if let Some(kind) = icon_kind_from_value(&entry.icon) {
        return kind;
    }

    let text = format!(
        "{} {} {} {}",
        entry.title, entry.url, entry.username, entry.group
    )
    .to_lowercase();

    if contains_any(&text, &["youtube", "youtu.be"]) {
        SecretIconKind::Youtube
    } else if contains_any(&text, &["google"]) {
        SecretIconKind::Google
    } else if contains_any(&text, &["github"]) {
        SecretIconKind::Github
    } else if contains_any(&text, &["instagram"]) {
        SecretIconKind::Instagram
    } else if contains_any(&text, &["facebook"]) {
        SecretIconKind::Facebook
    } else if contains_any(&text, &["netflix"]) {
        SecretIconKind::Netflix
    } else if contains_any(&text, &["spotify"]) {
        SecretIconKind::Spotify
    } else if contains_any(&text, &["amazon"]) {
        SecretIconKind::Amazon
    } else if contains_any(&text, &["apple", "icloud"]) {
        SecretIconKind::Apple
    } else if contains_any(&text, &["microsoft", "outlook", "office"]) {
        SecretIconKind::Microsoft
    } else if contains_any(&text, &["bank", "banco", "finance", "finanza", "paypal"]) {
        SecretIconKind::Bank
    } else if contains_any(&text, &["shop", "tienda", "store", "mercado"]) {
        SecretIconKind::Cart
    } else if contains_any(&text, &["drive", "dropbox", "cloud", "nube"]) {
        SecretIconKind::Cloud
    } else if contains_any(&text, &["gitlab", "bitbucket", "code", "dev"]) {
        SecretIconKind::Code
    } else if contains_any(&text, &["steam", "xbox", "playstation", "game", "juego"]) {
        SecretIconKind::Game
    } else if contains_any(&text, &["mail", "correo", "gmail", "email"]) {
        SecretIconKind::Mail
    } else if contains_any(&text, &["media", "video"]) {
        SecretIconKind::Media
    } else if contains_any(&text, &["server", "ssh", "vps", "hosting", "servidor"]) {
        SecretIconKind::Server
    } else if contains_any(
        &text,
        &["facebook", "instagram", "twitter", "x.com", "social"],
    ) {
        SecretIconKind::Social
    } else if entry.url.trim().is_empty() {
        SecretIconKind::Key
    } else {
        SecretIconKind::Globe
    }
}

fn icon_kind_from_value(value: &str) -> Option<SecretIconKind> {
    match value.trim().to_lowercase().as_str() {
        "amazon" => Some(SecretIconKind::Amazon),
        "apple" => Some(SecretIconKind::Apple),
        "bank" => Some(SecretIconKind::Bank),
        "cart" => Some(SecretIconKind::Cart),
        "cloud" => Some(SecretIconKind::Cloud),
        "code" => Some(SecretIconKind::Code),
        "facebook" => Some(SecretIconKind::Facebook),
        "game" => Some(SecretIconKind::Game),
        "github" => Some(SecretIconKind::Github),
        "globe" => Some(SecretIconKind::Globe),
        "google" => Some(SecretIconKind::Google),
        "instagram" => Some(SecretIconKind::Instagram),
        "key" => Some(SecretIconKind::Key),
        "mail" => Some(SecretIconKind::Mail),
        "media" => Some(SecretIconKind::Media),
        "microsoft" => Some(SecretIconKind::Microsoft),
        "netflix" => Some(SecretIconKind::Netflix),
        "server" => Some(SecretIconKind::Server),
        "social" => Some(SecretIconKind::Social),
        "spotify" => Some(SecretIconKind::Spotify),
        "youtube" => Some(SecretIconKind::Youtube),
        _ => None,
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn password_strength(password: &str) -> PasswordStrength {
    if password.is_empty() {
        return PasswordStrength {
            level: 0,
            percent: 0,
            label: "Vacía",
            hint: "Agrega una contraseña para evaluar su fuerza.",
        };
    }

    let length = password.chars().count();
    let has_lower = password.chars().any(|char| char.is_ascii_lowercase());
    let has_upper = password.chars().any(|char| char.is_ascii_uppercase());
    let has_number = password.chars().any(|char| char.is_ascii_digit());
    let has_symbol = password.chars().any(|char| !char.is_ascii_alphanumeric());
    let variety = [has_lower, has_upper, has_number, has_symbol]
        .into_iter()
        .filter(|value| *value)
        .count();
    let mut score = 0;

    score += match length {
        0..=7 => 0,
        8..=11 => 1,
        12..=15 => 2,
        _ => 3,
    };
    score += variety;

    match score {
        0..=2 => PasswordStrength {
            level: 1,
            percent: 25,
            label: "Débil",
            hint: "Usa al menos 12 caracteres y mezcla letras, números y símbolos.",
        },
        3..=4 => PasswordStrength {
            level: 2,
            percent: 50,
            label: "Media",
            hint: "Mejora la longitud o agrega más variedad de caracteres.",
        },
        5 => PasswordStrength {
            level: 3,
            percent: 75,
            label: "Buena",
            hint: "Buena contraseña; 16+ caracteres sería aún mejor.",
        },
        _ => PasswordStrength {
            level: 4,
            percent: 100,
            label: "Fuerte",
            hint: "Buena longitud y variedad.",
        },
    }
}

fn risk_summary(entry: &SecretEntry, entries: &[SecretEntry]) -> RiskSummary {
    let password = entry.password.trim();
    let reused = !password.is_empty()
        && entries
            .iter()
            .filter(|candidate| candidate.password == entry.password)
            .count()
            > 1;
    let similar = !reused
        && !password.is_empty()
        && entries
            .iter()
            .filter(|candidate| candidate.id != entry.id)
            .map(|candidate| candidate.password.trim())
            .filter(|candidate| !candidate.is_empty())
            .any(|candidate| password_similarity_ratio(password, candidate) >= 0.75);
    let domain = normalized_domain(&entry.url);
    let duplicated_domain = domain.as_ref().is_some_and(|domain| {
        entries
            .iter()
            .filter(|candidate| candidate.id != entry.id)
            .filter_map(|candidate| normalized_domain(&candidate.url))
            .any(|candidate_domain| candidate_domain == *domain)
    });
    let exposed = password_exposure_signals(password);
    let old_password = password_age_days(entry).is_some_and(|days| days >= 180.0);

    RiskSummary {
        weak: password_strength(password).level <= 2,
        reused,
        similar,
        duplicated_domain,
        exposed,
        old_password,
        missing_url: entry.url.trim().is_empty(),
        missing_username: entry.username.trim().is_empty(),
        has_history: !entry.password_history.is_empty(),
    }
}

fn entry_has_risk(entry: &SecretEntry, entries: &[SecretEntry]) -> bool {
    let risk = risk_summary(entry, entries);
    risk.weak
        || risk.reused
        || risk.similar
        || risk.duplicated_domain
        || risk.exposed
        || risk.old_password
        || risk.missing_url
        || risk.missing_username
}

fn vault_audit_summary(entries: &[SecretEntry]) -> VaultAuditSummary {
    let mut weak_count = 0;
    let mut reused_count = 0;
    let mut similar_count = 0;
    let mut duplicate_domain_count = 0;
    let mut exposed_count = 0;
    let mut old_password_count = 0;
    let mut total_risks = 0usize;

    for entry in entries {
        let risk = risk_summary(entry, entries);
        weak_count += usize::from(risk.weak);
        reused_count += usize::from(risk.reused);
        similar_count += usize::from(risk.similar);
        duplicate_domain_count += usize::from(risk.duplicated_domain);
        exposed_count += usize::from(risk.exposed);
        old_password_count += usize::from(risk.old_password);
        total_risks += usize::from(risk.weak)
            + usize::from(risk.reused)
            + usize::from(risk.similar)
            + usize::from(risk.duplicated_domain)
            + usize::from(risk.exposed)
            + usize::from(risk.old_password)
            + usize::from(risk.missing_url)
            + usize::from(risk.missing_username);
    }

    let max_risk_points = (entries.len() * 8) as f64;
    let score = if entries.is_empty() || max_risk_points <= 0.0 {
        100
    } else {
        let ratio = (total_risks as f64 / max_risk_points).clamp(0.0, 1.0);
        ((1.0 - ratio) * 100.0).round() as u8
    };

    VaultAuditSummary {
        score,
        weak_count,
        reused_count,
        similar_count,
        duplicate_domain_count,
        exposed_count,
        old_password_count,
    }
}

fn security_action_items(entries: &[SecretEntry]) -> Vec<SecurityActionItem> {
    let mut items = entries
        .iter()
        .filter_map(|entry| {
            let risk = risk_summary(entry, entries);
            let mut reasons = Vec::<String>::new();
            let mut priority = 0u8;

            if risk.reused {
                priority = priority.saturating_add(40);
                reasons.push("Reutilizada".to_string());
            }
            if risk.exposed {
                priority = priority.saturating_add(35);
                reasons.push("Patrones expuestos".to_string());
            }
            if risk.weak {
                priority = priority.saturating_add(25);
                reasons.push("Débil".to_string());
            }
            if risk.similar {
                priority = priority.saturating_add(20);
                reasons.push("Similar a otra".to_string());
            }
            if risk.old_password {
                priority = priority.saturating_add(15);
                reasons.push("Antigua".to_string());
            }
            if risk.duplicated_domain {
                priority = priority.saturating_add(10);
                reasons.push("Dominio repetido".to_string());
            }
            if risk.missing_username {
                priority = priority.saturating_add(5);
                reasons.push("Sin usuario".to_string());
            }
            if risk.missing_url {
                priority = priority.saturating_add(5);
                reasons.push("Sin URL".to_string());
            }

            if priority == 0 {
                None
            } else {
                Some(SecurityActionItem {
                    entry_id: entry.id.clone(),
                    title: entry.title.clone(),
                    priority,
                    reasons,
                })
            }
        })
        .collect::<Vec<_>>();

    items.sort_by(|left, right| right.priority.cmp(&left.priority));
    items.truncate(3);
    items
}

#[component]
fn VaultAuditOverview(audit: VaultAuditSummary, is_dark_mode: bool, compact: bool) -> Element {
    let shell_class = if compact {
        if is_dark_mode {
            "mt-4 border border-white/10 bg-white/[0.04] p-4"
        } else {
            "mt-4 border border-vault-200 bg-vault-50 p-4"
        }
    } else if is_dark_mode {
        "mx-4 mt-4 border border-white/10 bg-white/[0.04] p-4 sm:mx-6"
    } else {
        "mx-4 mt-4 border border-vault-200 bg-vault-50 p-4 sm:mx-6"
    };
    let title_class = if is_dark_mode {
        "text-sm font-semibold text-white"
    } else {
        "text-sm font-semibold text-vault-950"
    };
    let score_class = if audit.score >= 85 {
        "text-emerald-500"
    } else if audit.score >= 65 {
        "text-amber-500"
    } else {
        "text-red-500"
    };
    let item_class = if is_dark_mode {
        "rounded-full bg-white/10 px-2.5 py-1 text-xs text-vault-300"
    } else {
        "rounded-full bg-white px-2.5 py-1 text-xs text-vault-600"
    };

    rsx! {
        section { class: "{shell_class}",
            div { class: "flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between",
                div {
                    p { class: "{title_class}", "Auditoría de seguridad avanzada" }
                    p { class: "mt-1 text-xs text-vault-500", "Detecta reuso, similitud, dominio duplicado, exposición y antigüedad." }
                }
                p { class: "text-2xl font-bold {score_class}", "{audit.score}/100" }
            }
            div { class: "mt-3 flex flex-wrap gap-2",
                span { class: "{item_class}", "Débiles: {audit.weak_count}" }
                span { class: "{item_class}", "Reutilizadas: {audit.reused_count}" }
                span { class: "{item_class}", "Similares: {audit.similar_count}" }
                span { class: "{item_class}", "Dominios duplicados: {audit.duplicate_domain_count}" }
                span { class: "{item_class}", "Expuestas: {audit.exposed_count}" }
                span { class: "{item_class}", "Antiguas: {audit.old_password_count}" }
            }
        }
    }
}

#[component]
fn VaultSecurityActionCenter(
    items: Vec<SecurityActionItem>,
    is_dark_mode: bool,
    on_select: EventHandler<String>,
    compact: bool,
) -> Element {
    let shell_class = if compact {
        if is_dark_mode {
            "mt-4 border border-white/10 bg-white/[0.03] p-4"
        } else {
            "mt-4 border border-vault-200 bg-white p-4"
        }
    } else if is_dark_mode {
        "mx-4 mt-3 border border-white/10 bg-white/[0.03] p-4 sm:mx-6"
    } else {
        "mx-4 mt-3 border border-vault-200 bg-white p-4 sm:mx-6"
    };
    let title_class = if is_dark_mode {
        "text-sm font-semibold text-white"
    } else {
        "text-sm font-semibold text-vault-950"
    };
    let item_class = if is_dark_mode {
        "border border-white/10 bg-vault-950/40 p-3"
    } else {
        "border border-vault-200 bg-vault-50 p-3"
    };
    let item_title_class = if is_dark_mode {
        "truncate text-sm font-semibold text-vault-100"
    } else {
        "truncate text-sm font-semibold text-vault-900"
    };
    let priority_class = if is_dark_mode {
        "rounded-full bg-red-500/20 px-2 py-0.5 text-xs font-semibold text-red-200"
    } else {
        "rounded-full bg-red-100 px-2 py-0.5 text-xs font-semibold text-red-700"
    };
    let review_button_class = if is_dark_mode {
        "border border-white/10 px-3 py-1.5 text-xs font-semibold text-brand-300 transition hover:bg-white/10"
    } else {
        "border border-vault-200 bg-white px-3 py-1.5 text-xs font-semibold text-brand-600 transition hover:bg-vault-100"
    };

    rsx! {
        section { class: "{shell_class}",
            div { class: "flex items-center justify-between gap-3",
                p { class: "{title_class}", "Centro de seguridad (prioridad)" }
                span { class: "text-xs text-vault-500", "{items.len()} acciones sugeridas" }
            }
            if items.is_empty() {
                p { class: "mt-3 text-sm text-vault-500", "No hay acciones urgentes. Tu bóveda está en buen estado." }
            } else {
                div { class: "mt-3 grid gap-2",
                    for item in items {
                        div { key: "{item.entry_id}", class: "{item_class}",
                            div { class: "flex items-start justify-between gap-3",
                                div { class: "min-w-0",
                                    p { class: "{item_title_class}", "{item.title}" }
                                    p { class: "mt-1 text-xs text-vault-400", "{item.reasons.join(\" · \")}" }
                                }
                                span { class: "{priority_class}", "P{item.priority}" }
                            }
                            div { class: "mt-3 flex justify-end",
                                button {
                                    class: "{review_button_class}",
                                    r#type: "button",
                                    onclick: move |_| on_select.call(item.entry_id.clone()),
                                    "Revisar secreto"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn normalized_domain(url: &str) -> Option<String> {
    let trimmed = url.trim().to_lowercase();
    if trimmed.is_empty() {
        return None;
    }

    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(&trimmed);
    let host = without_scheme.split('/').next().unwrap_or_default().trim();
    let host = host.strip_prefix("www.").unwrap_or(host);
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

fn password_similarity_ratio(left: &str, right: &str) -> f64 {
    if left == right {
        return 1.0;
    }

    let left = left.to_lowercase();
    let right = right.to_lowercase();
    let left_chars = left.chars().collect::<Vec<_>>();
    let right_chars = right.chars().collect::<Vec<_>>();
    if left_chars.is_empty() || right_chars.is_empty() {
        return 0.0;
    }

    let max_len = left_chars.len().max(right_chars.len()) as f64;
    let min_len = left_chars.len().min(right_chars.len());
    let positional_matches = (0..min_len)
        .filter(|index| left_chars[*index] == right_chars[*index])
        .count() as f64;
    let overlap = positional_matches / max_len;

    let left_unique = left_chars
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let right_unique = right_chars
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    let intersection = left_unique.intersection(&right_unique).count() as f64;
    let union = left_unique.union(&right_unique).count() as f64;
    let jaccard = if union > 0.0 {
        intersection / union
    } else {
        0.0
    };

    (overlap * 0.6) + (jaccard * 0.4)
}

fn password_exposure_signals(password: &str) -> bool {
    let lower = password.trim().to_lowercase();
    if lower.is_empty() {
        return false;
    }

    let common = [
        "password",
        "qwerty",
        "admin",
        "123456",
        "123456789",
        "letmein",
        "welcome",
        "secret",
    ];
    if common.iter().any(|term| lower.contains(term)) {
        return true;
    }

    if lower.chars().all(|char| char.is_ascii_digit()) {
        return true;
    }

    lower.contains("1234") || lower.contains("abcd")
}

fn password_age_days(entry: &SecretEntry) -> Option<f64> {
    #[cfg(target_arch = "wasm32")]
    {
        let updated_at = entry.updated_at.trim();
        if updated_at.is_empty() {
            return None;
        }

        let timestamp_ms = js_sys::Date::parse(updated_at);
        if timestamp_ms.is_nan() {
            return None;
        }

        let diff_ms = (js_sys::Date::now() - timestamp_ms).max(0.0);
        return Some(diff_ms / 86_400_000.0);
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = entry;
        None
    }
}

fn format_history_timestamp(timestamp: i64) -> String {
    #[cfg(target_arch = "wasm32")]
    {
        let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(timestamp as f64 * 1000.0));
        return date
            .to_locale_string("es-ES", &wasm_bindgen::JsValue::UNDEFINED)
            .into();
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        format!("Cambio guardado ({timestamp})")
    }
}

fn import_preview_item_key(item: &tauri_api::ImportPreviewItem) -> String {
    format!(
        "{}|{}|{}",
        normalize_text_key(&item.title),
        normalize_text_key(&item.username),
        normalize_text_key(&item.url)
    )
}

fn existing_entry_key(entry: &SecretEntry) -> String {
    format!(
        "{}|{}|{}",
        normalize_text_key(&entry.title),
        normalize_text_key(&entry.username),
        normalize_text_key(&entry.url)
    )
}

fn normalize_text_key(value: &str) -> String {
    value.trim().to_lowercase()
}

struct ImportDuplicateStats {
    total: usize,
    in_file: usize,
    in_vault: usize,
}

fn import_duplicate_stats(
    items: &[tauri_api::ImportPreviewItem],
    existing_entries: &[SecretEntry],
) -> ImportDuplicateStats {
    let mut in_file_counts = std::collections::HashMap::<String, usize>::new();
    for item in items {
        let key = import_preview_item_key(item);
        *in_file_counts.entry(key).or_insert(0) += 1;
    }

    let mut total = 0usize;
    let mut in_file = 0usize;
    let mut in_vault = 0usize;

    for item in items {
        let key = import_preview_item_key(item);
        let duplicated_in_file = in_file_counts.get(&key).copied().unwrap_or(0) > 1;
        let duplicated_in_vault = existing_entries
            .iter()
            .any(|entry| existing_entry_key(entry) == key);
        if duplicated_in_file || duplicated_in_vault {
            total += 1;
        }
        if duplicated_in_file {
            in_file += 1;
        }
        if duplicated_in_vault {
            in_vault += 1;
        }
    }

    ImportDuplicateStats {
        total,
        in_file,
        in_vault,
    }
}

fn initials(title: &str) -> String {
    let mut chars = title
        .split_whitespace()
        .filter_map(|part| part.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase();

    if chars.is_empty() {
        chars = "SS".to_string();
    }

    chars
}

fn mode_button_class(active: bool, is_dark_mode: bool) -> &'static str {
    match (active, is_dark_mode) {
        (true, true) => "-mb-px border-b-2 border-brand-400 px-5 py-3 text-sm font-semibold text-white",
        (false, true) => "-mb-px border-b-2 border-transparent px-5 py-3 text-sm text-vault-400 transition hover:text-white",
        (true, false) => "-mb-px border-b-2 border-vault-950 px-5 py-3 text-sm font-semibold text-vault-950",
        (false, false) => "-mb-px border-b-2 border-transparent px-5 py-3 text-sm text-vault-500 transition hover:text-vault-950",
    }
}
