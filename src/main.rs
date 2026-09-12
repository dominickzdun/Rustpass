#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![expect(rustdoc::missing_crate_level_docs)]

use chacha20poly1305::Key;
use eframe::egui;
use egui_file_dialog::FileDialog;
use std::env;
use std::path::PathBuf;

use crate::database::Entry;

mod database;
mod gui_handler;

fn main() -> eframe::Result {
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).

    // program should be single threaded? so its probably okay
    unsafe {
        env::set_var("WGPU_BACKEND", "opengl"); // need to set this for windows so vulkan doesnt hog cpu
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([720.0, 480.0]),
        vsync: false,
        ..Default::default()
    };

    eframe::run_native(
        "Rustpass",
        options,
        Box::new(|cc| Ok(Box::new(MyApp::new(cc)))),
    )
}

#[derive(Default, PartialEq)]
enum ViewState {
    #[default]
    StartMenu,
    UnlockDatabase,
    DatabaseStartMenu,
    NewEntry,
    EditEntry,
    FullEntry,
}

#[derive(Default)]
struct MyApp {
    viewstate: ViewState,
    show_new_db_viewport: bool,
    db_selected: bool,
    new_db_name: String,
    new_db_page: i32,
    new_db_password: String,
    new_db_confirm_password: String,
    password: String,
    key: Key,
    file_dialog: FileDialog,
    file_path: Option<PathBuf>,
    pending_create: bool,
    pending_open: bool,
    unlocked_db: bool,
    new_entry: database::Entry,
    loaded_entries: Vec<database::EncryptedEntry>,
    full_entry_index: usize,
    hide_password: bool,
}

impl MyApp {
    pub fn reset_app_state(&mut self) {
        *self = Self::default();
    }

    pub fn new(_cc: &eframe::CreationContext) -> Self {
        Self {
            viewstate: ViewState::StartMenu,
            show_new_db_viewport: false,
            db_selected: false,
            new_db_name: String::new(),
            new_db_page: 0,
            new_db_password: String::new(),
            new_db_confirm_password: String::new(),
            password: String::new(),
            key: Key::from([0u8; 32]),
            file_dialog: FileDialog::new(),
            file_path: None,
            pending_create: false,
            pending_open: false,
            unlocked_db: false,
            new_entry: Entry::new(String::new(), String::new(), String::new()),
            loaded_entries: Vec::new(),
            full_entry_index: 0,
            hide_password: true,
        }
    }
}

impl eframe::App for MyApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.set_pixels_per_point(1.75);
            self.header(ui);
            if self.viewstate == ViewState::StartMenu {
                self.start_menu(ui);
            } else if self.viewstate == ViewState::UnlockDatabase {
                self.unlock_db(ui);
            } else if self.viewstate == ViewState::DatabaseStartMenu {
                self.unlocked_db(ui);
            } else if self.viewstate == ViewState::NewEntry {
                self.new_entry(ui);
            } else if self.viewstate == ViewState::EditEntry {
                self.load_edit_entry(ui, self.full_entry_index);
            } else if self.viewstate == ViewState::FullEntry {
                self.load_full_entry(ui);
            }

            self.show_new_db_viewport_ui(ui); //automatically handles itself based on state

            if (self.pending_create || self.pending_open)
                && let Some(path) = self.file_dialog.update(ui).picked()
            {
                self.file_path = Some(path.to_path_buf());
            }

            if self.pending_create {
                if let Some(path) = &self.file_path {
                    self.key = database::create_db(&self.new_db_password, path);
                    self.reset_new_db_state();
                    self.file_path = None;
                }
            } else if self.pending_open {
                self.password = String::new();
                self.unlocked_db = false;
                self.db_selected = true;
                self.viewstate = ViewState::UnlockDatabase;
                self.pending_open = false;
            }
        });
    }
}
