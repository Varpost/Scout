// This file is intentionally insecure — used for testing Scout scanners.
// DO NOT use this code in production.

const express = require('express');
const app = express();
const mysql = require('mysql');

// No helmet — missing security headers
// No rate limiting

// Wildcard CORS
app.use(require('cors')());

// SQL Injection — string concatenation
app.get('/user', (req, res) => {
    const userId = req.query.id;
    db.query("SELECT * FROM users WHERE id = '" + userId + "'", (err, results) => {
        res.json(results);
    });
});

// XSS via innerHTML
app.get('/page', (req, res) => {
    const name = req.query.name;
    res.send(`<div id="greeting"></div><script>
        document.getElementById('greeting').innerHTML = '${name}';
    </script>`);
});

// Command injection via user input
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 1 ${host}`, (err, stdout) => {
        res.send(stdout);
    });
});

// Hardcoded secret (generic pattern for testing)
const DB_PASSWORD = "production_db_password_123";

app.listen(3000);
