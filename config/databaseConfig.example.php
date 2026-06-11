<?php
/**
 * Database Configuration
 * Copy this file to databaseConfig.php and fill in real values.
 * Never commit databaseConfig.php to version control.
 */

$conn = new mysqli(
    getenv('DB_HOST')     ?: 'localhost',
    getenv('DB_USER')     ?: 'your_db_user',
    getenv('DB_PASSWORD') ?: 'your_db_password',
    getenv('DB_NAME')     ?: 'your_db_name',
    (int)(getenv('DB_PORT') ?: 3306)
);

if ($conn->connect_error) {
    error_log('Database connection failed: ' . $conn->connect_error);
    http_response_code(503);
    die('Service temporarily unavailable.');
}

$conn->set_charset('utf8mb4');
