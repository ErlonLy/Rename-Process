# ui/main_window.py
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QLabel, QPushButton, 
                             QFileDialog, QMessageBox, QTextEdit, QHBoxLayout,
                             QCheckBox, QSpinBox)
from PyQt5.QtCore import Qt, QTimer
import os
import time

from core.loader import run_hollowing, start_continuous_hollowing, stop_continuous_hollowing, is_hollowing_active

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Process Hollowing Demo - Modo Contínuo")
        self.setFixedSize(600, 500)

        layout = QVBoxLayout()

        # Seleção de arquivos
        self.label_target = QLabel("Executável alvo: (não selecionado)")
        self.label_host = QLabel("Processo host: (não selecionado)")

        self.btn_target = QPushButton("Selecionar alvo")
        self.btn_host = QPushButton("Selecionar host (ex: svchost.exe)")
        
        # Modo contínuo
        continuous_layout = QHBoxLayout()
        self.cb_continuous = QCheckBox("Modo Contínuo")
        self.spin_interval = QSpinBox()
        self.spin_interval.setRange(1, 60)
        self.spin_interval.setValue(5)
        self.spin_interval.setSuffix(" segundos")
        continuous_layout.addWidget(self.cb_continuous)
        continuous_layout.addWidget(QLabel("Intervalo:"))
        continuous_layout.addWidget(self.spin_interval)
        continuous_layout.addStretch()

        # Botões de ação
        self.btn_run = QPushButton("Executar Hollowing")
        self.btn_stop = QPushButton("Parar Hollowing")
        self.btn_stop.setEnabled(False)
        
        # Log
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(200)

        # Conectar sinais
        self.btn_target.clicked.connect(self.select_target)
        self.btn_host.clicked.connect(self.select_host)
        self.btn_run.clicked.connect(self.run_hollowing)
        self.btn_stop.clicked.connect(self.stop_hollowing)
        self.cb_continuous.stateChanged.connect(self.toggle_continuous_mode)

        # Layout
        layout.addWidget(self.label_target)
        layout.addWidget(self.btn_target)
        layout.addWidget(self.label_host)
        layout.addWidget(self.btn_host)
        layout.addLayout(continuous_layout)
        
        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.btn_run)
        buttons_layout.addWidget(self.btn_stop)
        layout.addLayout(buttons_layout)
        
        layout.addWidget(QLabel("Log de Execução:"))
        layout.addWidget(self.log_output)

        self.setLayout(layout)

        self.target = None
        self.host = None
        
        # Timer para verificar status
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(1000)  # 1 segundo

    def select_target(self):
        file, _ = QFileDialog.getOpenFileName(self, "Escolher executável alvo", "", "Executáveis (*.exe)")
        if file:
            self.target = file
            self.label_target.setText(f"Executável alvo: {os.path.basename(file)}")
            self.log(f"Alvo selecionado: {file}")

    def select_host(self):
        file, _ = QFileDialog.getOpenFileName(self, "Escolher executável host", "", "Executáveis (*.exe)")
        if file:
            self.host = file
            self.label_host.setText(f"Processo host: {os.path.basename(file)}")
            self.log(f"Host selecionado: {file}")

    def run_hollowing(self):
        if not self.target:
            QMessageBox.warning(self, "Erro", "Selecione um alvo primeiro.")
            return

        if self.cb_continuous.isChecked():
            # Modo contínuo
            interval = self.spin_interval.value()
            if start_continuous_hollowing(self.target, interval):
                self.log(f"Iniciando hollowing contínuo (intervalo: {interval}s)")
                self.btn_run.setEnabled(False)
                self.btn_stop.setEnabled(True)
                self.cb_continuous.setEnabled(False)
            else:
                self.log("Falha ao iniciar hollowing contínuo")
        else:
            # Modo único
            if not self.host:
                QMessageBox.warning(self, "Erro", "Selecione um host primeiro para modo único.")
                return
            
            self.log("Iniciando hollowing único...")
            success = run_hollowing(self.target, self.host)
            
            if success:
                self.log("Hollowing executado com sucesso!")
                QMessageBox.information(self, "Sucesso", "Processo de hollowing concluído.")
            else:
                self.log("Falha no processo de hollowing.")
                QMessageBox.warning(self, "Erro", "Falha ao executar hollowing.")

    def stop_hollowing(self):
        stop_continuous_hollowing()
        self.log("Hollowing contínuo parado")
        self.btn_run.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.cb_continuous.setEnabled(True)

    def toggle_continuous_mode(self, state):
        if state == Qt.Checked:
            self.btn_host.setEnabled(False)
            self.label_host.setText("Processo host: (automático - modo contínuo)")
        else:
            self.btn_host.setEnabled(True)
            if self.host:
                self.label_host.setText(f"Processo host: {os.path.basename(self.host)}")
            else:
                self.label_host.setText("Processo host: (não selecionado)")

    def update_status(self):
        if is_hollowing_active():
            self.btn_run.setEnabled(False)
            self.btn_stop.setEnabled(True)
        else:
            self.btn_run.setEnabled(True)
            self.btn_stop.setEnabled(False)

    def log(self, message):
        self.log_output.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        # Rolagem automática para o final
        self.log_output.verticalScrollBar().setValue(
            self.log_output.verticalScrollBar().maximum()
        )

    def closeEvent(self, event):
        """Garante que para o hollowing ao fechar a janela"""
        if is_hollowing_active():
            stop_continuous_hollowing()
        event.accept()