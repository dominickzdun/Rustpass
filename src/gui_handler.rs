use crate::MyApp;
use crate::ViewState;
use crate::ViewState::NewEntry;
use crate::database;
use eframe::egui;
use egui::{Frame, Label, RichText, Sense, UiBuilder, Widget as _};
use rfd::FileDialog;
use zeroize::Zeroize;

impl MyApp {
    pub fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.menu_button("Database", |ui| {
                if ui.button("Create New Database").clicked() {
                    self.show_new_db_viewport = true;
                    ui.close();
                }

                if ui.button("Open Database").clicked() {
                    self.file_path = FileDialog::new()
                        .add_filter("database", &["enc"])
                        .set_directory("/")
                        .pick_file();
                    self.pending_open = true;
                    ui.close();
                }

                if ui.button("Lock Database").clicked() && self.unlocked_db {
                    self.reset_app_state();
                    ui.close();
                }

                if ui.button("Quit").clicked() {
                    ui.close();
                }
            });
            ui.menu_button("Entries", |ui| {
                if ui.button("New Entry").clicked() && self.unlocked_db {
                    self.reset_loaded_single_entry();
                    self.viewstate = NewEntry;
                    ui.close();
                }
            });
        });
    }

    pub fn show_new_db_viewport_ui(&mut self, ui: &mut egui::Ui) {
        if self.show_new_db_viewport {
            ui.ctx().show_viewport_immediate(
                egui::ViewportId::from_hash_of("immediate_viewport"),
                egui::ViewportBuilder::default()
                    .with_title("Create new database")
                    .with_inner_size([720.0, 320.0]),
                |ui, _class| {
                    egui::CentralPanel::default().show_inside(ui, |ui| {
                        if self.new_db_page == 1 {
                            ui.label("Password");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_db_password)
                                    .password(true),
                            );

                            ui.label("Confirm Password");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.new_db_confirm_password)
                                    .password(true),
                            );

                            ui.horizontal(|ui| {
                                if ui.button("Go Back").clicked() {
                                    self.new_db_page -= 1;
                                }
                                if ui.button("Done").clicked()
                                    && self.new_db_password == self.new_db_confirm_password
                                {
                                    self.file_path = FileDialog::new()
                                        .set_file_name(&format!("{}.enc", self.new_db_name))
                                        .save_file();
                                    self.pending_create = true;
                                }
                            });
                        } else {
                            //Page 0
                            ui.heading("Database Information");
                            ui.label("Database Name ");
                            ui.text_edit_singleline(&mut self.new_db_name);
                            ui.horizontal(|ui| {
                                if ui.button("Cancel").clicked() {
                                    self.new_db_name = String::new();
                                    self.new_db_page = 0;
                                    self.new_db_password = String::new();
                                    self.new_db_confirm_password = String::new();

                                    self.show_new_db_viewport = false;
                                }
                                if ui.button("Continue").clicked() {
                                    self.new_db_page += 1;
                                }
                            });
                        }

                        if ui.input(|i| i.viewport().close_requested()) {
                            self.show_new_db_viewport = false;
                        }
                    });
                },
            );
        }
    }
    pub fn reset_new_db_state(&mut self) {
        self.pending_create = false;
        self.file_path = None;

        //REMOVE VIEWPORT AND RESET STATE
        self.show_new_db_viewport = false;
        self.new_db_name = String::new();
        self.new_db_page = 0;
        self.new_db_password = String::new();
        self.new_db_confirm_password = String::new();
    }
    pub fn start_menu(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(25.0);

            ui.heading("Rustpass");

            ui.add_space(10.0);

            if ui
                .add_sized([150.0, 30.0], egui::Button::new("Create New Database"))
                .clicked()
            {
                self.show_new_db_viewport = true;
            }

            if ui
                .add_sized([150.0, 30.0], egui::Button::new("Open Database"))
                .clicked()
            {
                self.file_path = FileDialog::new()
                    .add_filter("database", &["enc"])
                    .pick_file();
                self.pending_open = true;
            }
        });
    }

    pub fn unlock_db(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Your password: ");
            ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
        });
        if ui.button("Enter").clicked() {
            // take password, generate key, compare key to hash, if true store key,
            // else give error message
            match database::unlock_db(&self.password, &self.file_path) {
                Ok(key) => {
                    self.key = key;
                    self.db_selected = false;
                    self.unlocked_db = true;
                    self.viewstate = ViewState::DatabaseStartMenu;
                    self.decrypt_all_entries();
                }
                Err(e) => println!("{}", e),
            }
        }
    }

    pub fn unlocked_db(&mut self, ui: &mut egui::Ui) {
        for entry in 0..self.loaded_entries.len() {
            self.load_entry_listing(ui, entry);
        }
    }
    pub fn new_entry(&mut self, ui: &mut egui::Ui) {
        ui.label("Title");
        ui.text_edit_singleline(&mut self.new_entry.title);
        ui.label("Username");
        ui.text_edit_singleline(&mut self.new_entry.username);

        ui.label("Password");
        ui.add(egui::TextEdit::singleline(&mut self.new_entry.password).password(true));
        if ui.button("Create").clicked() {
            //cipher text, write to file to save cipher, nonce,
            match self.create_new_entry() {
                Ok(_) => {
                    self.loaded_entries.clear();
                    self.decrypt_all_entries();

                    self.new_entry.title.zeroize();
                    self.new_entry.username.zeroize();
                    self.new_entry.password.zeroize();
                    self.viewstate = ViewState::DatabaseStartMenu;
                }
                Err(e) => {
                    eprintln!("Failed to create new entry: {}", e);
                }
            }
        }
        if ui.button("Cancel").clicked() {
            self.viewstate = ViewState::DatabaseStartMenu;
        }
    }

    pub fn load_edit_entry(&mut self, ui: &mut egui::Ui, index: usize) {
        ui.strong("Title");
        ui.text_edit_singleline(&mut self.new_entry.title);
        ui.strong("Username");
        ui.text_edit_singleline(&mut self.new_entry.username);

        ui.strong("Password");
        ui.add(
            egui::TextEdit::singleline(&mut self.new_entry.password).password(self.hide_password),
        );
        if ui.button("View Password").clicked() {
            self.hide_password = !self.hide_password;
        }
        if ui.button("Change").clicked() {
            let _ = self.update_entry(index, self.new_entry.clone());
            self.reset_loaded_single_entry();
            self.viewstate = ViewState::DatabaseStartMenu;

            //reload all entry with newly added entry,
            //probably not the most efficient...
            self.loaded_entries.clear();
            self.decrypt_all_entries();
        }
        if ui.button("Cancel").clicked() {
            self.reset_loaded_single_entry();
            self.viewstate = ViewState::DatabaseStartMenu;
        }
    }

    pub fn load_full_entry(&mut self, ui: &mut egui::Ui) {
        ui.strong("Title");
        ui.strong(&self.new_entry.title);
        ui.strong("Username");
        ui.strong(&self.new_entry.username);

        ui.strong("Password");

        let shown = if self.hide_password {
            "•".repeat(self.new_entry.password.chars().count())
        } else {
            self.new_entry.password.clone()
        };
        ui.label(
            egui::RichText::new(shown)
                .strong()
                .color(ui.style().visuals.strong_text_color()),
        );
        let view_label = if self.hide_password {
            "View Password"
        } else {
            "Hide Password"
        };
        if ui.button(view_label).clicked() {
            self.hide_password = !self.hide_password;
        }
        if ui.button("Go Back").clicked() {
            self.reset_loaded_single_entry();
            self.viewstate = ViewState::DatabaseStartMenu;
        }
    }

    pub fn load_entry_listing(&mut self, ui: &mut egui::Ui, index: usize) {
        // needed for delete function
        if index >= self.loaded_entries.len() {
            return;
        }
        let response = ui
            .scope_builder(
                UiBuilder::new()
                    .id_salt(("entry", index))
                    .sense(Sense::click()),
                |ui| {
                    let response = ui.response();
                    let visuals = ui.style().interact(&response);
                    let text_color = visuals.text_color();

                    Frame::canvas(ui.style())
                        .fill(visuals.bg_fill.gamma_multiply(0.3))
                        .stroke(visuals.bg_stroke)
                        .inner_margin(ui.spacing().menu_margin)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());

                            ui.horizontal(|ui| {
                                ui.add_space(32.0);

                                ui.label(
                                    RichText::new(&self.loaded_entries[index].title)
                                        .color(text_color)
                                        .size(16.0),
                                );

                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.add_space(8.0);

                                        ui.menu_button("More", |ui| {
                                            if ui.button("Edit").clicked() {
                                                self.full_entry_index = index;
                                                self.new_entry =
                                                    self.encrypted_payload_to_entry(index);
                                                self.hide_password = true;
                                                self.viewstate = ViewState::EditEntry;
                                                ui.close();
                                            }

                                            if ui.button("Delete").clicked() {
                                                self.delete_entry(index);
                                                self.loaded_entries.clear();
                                                // dont make it none then fill it X
                                                // get decypted entires then replace loaded entries
                                                self.decrypt_all_entries();
                                                ui.close();
                                            }
                                        });
                                        ui.menu_button("Copy", |ui| {
                                            if ui.button("Copy Username").clicked() {
                                                let entry = self.encrypted_payload_to_entry(index);

                                                if !entry.username.is_empty() {
                                                    ui.ctx().copy_text(entry.username);
                                                }

                                                ui.close();
                                            }

                                            if ui.button("Copy Password").clicked() {
                                                let entry = self.encrypted_payload_to_entry(index);

                                                ui.ctx().copy_text(entry.password);
                                                ui.close();
                                            }
                                        });
                                    },
                                );
                            });
                        });
                },
            )
            .response;

        if response.clicked() {
            self.full_entry_index = index;
            self.new_entry = self.encrypted_payload_to_entry(index);
            self.hide_password = true;
            self.viewstate = ViewState::FullEntry;
        }
    }
}
