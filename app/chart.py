from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Chart(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    tipe = db.Column(db.String(20), nullable=False)  # Misal: Encrypt, Decrypt, Embed, Extract
    nama_file = db.Column(db.String(100), nullable=False)
    waktu = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(100), nullable=False)  # Contoh: "Berhasil", "Gagal"

    def __repr__(self):
        return f"<Log {self.id} - {self.tipe} - {self.nama_file}>"
