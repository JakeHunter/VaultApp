import sys
from PyQt5.QtWidgets import QApplication
from gui import VaultApp

def main():
    app = QApplication(sys.argv)
    vault_app = VaultApp()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
