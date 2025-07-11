-- Tabel log_proses
CREATE TABLE log_proses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tipe VARCHAR(50) NOT NULL,
    nama_file VARCHAR(255) NOT NULL,
    waktu DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabel password
CREATE TABLE password (
    id INT AUTO_INCREMENT PRIMARY KEY,
    file_name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (file_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tambahkan di database.sql
CREATE TABLE admin_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO admin_users (username, password_hash) 
VALUES ('burung', '$2a$12$mRuG3z1U6lVz7Qy9Wq8UuOc5dNkXxYvZbLhA2fB3nC4gD5hE6jF7k');