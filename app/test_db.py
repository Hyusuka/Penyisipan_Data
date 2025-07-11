from app.utils.database import db_manager

def test_connection():
    print("🔄 Menguji koneksi database...")
    try:
        db_manager.init_pool()
        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SHOW TABLES")
            tables = cursor.fetchall()

            print("✅ Koneksi ke database berhasil!")

            if tables:
                print(f"📦 Tabel yang ditemukan ({len(tables)}):")
                for table in tables:
                    print(f" - {table[0]}")
            else:
                print("⚠️  Koneksi berhasil, namun tidak ada tabel di database.")
    except Exception as e:
        print(f"❌ Gagal terkoneksi ke database: {e}")

if __name__ == "__main__":
    test_connection()
