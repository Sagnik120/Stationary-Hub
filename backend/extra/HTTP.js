const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const app = express();

// Middleware to redirect HTTP to HTTPS
app.use((req, res, next) => {
    if (req.secure) {
        // If the request is already HTTPS, proceed
        next();
    } else {
        // Redirect to HTTPS
        res.redirect(`https://${req.hostname}:${req.app.get('port')}${req.url}`);
    }
});

// Your other routes here...

// HTTP Server
http.createServer(app).listen(8000, () => {
    console.log('HTTP Server running on http://localhost:8000');
});

// HTTPS Server
const options = {
    key: fs.readFileSync('localhost.key'),
    cert: fs.readFileSync('localhost.crt')
};

https.createServer(options, app).listen(8443, () => {
    console.log('HTTPS Server running on https://localhost:8443');
});
