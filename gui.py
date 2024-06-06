import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QFileDialog, QMessageBox
from vault import encrypt_file, decrypt_file

class VaultApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Secure File Vault')

        layout = QVBoxLayout()

        self.password_label = QLabel('Password')
        layout.addWidget(self.password_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.encrypt_button = QPushButton('Encrypt File')
        self.encrypt_button.clicked.connect(self.encrypt)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton('Decrypt File')
        self.decrypt_button.clicked.connect(self.decrypt)
        layout.addWidget(self.decrypt_button)

        self.setLayout(layout)
        self.show()

    def encrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File to Encrypt')
        if file_path:
            try:
                encrypt_file(self.password_input.text(), file_path)
                QMessageBox.information(self, 'Success', 'File encrypted successfully')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to encrypt file: {e}')

    def decrypt(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File to Decrypt')
        if file_path:
            try:
                decrypt_file(self.password_input.text(), file_path)
                QMessageBox.information(self, 'Success', 'File decrypted successfully')
            except Exception as e:
                QMessageBox.critical(self, 'Error', f'Failed to decrypt file: {e}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    vault_app = VaultApp()
    sys.exit(app.exec_())
