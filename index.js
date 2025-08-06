const express = require("express");
const app = express();
const port = process.env.PORT || 3000;
const crypto = require("crypto");

const KEYS = {}; // { HWID: { key, expiresAt } }

function generateKey(hwid) {
    const week = Math.floor(Date.now() / (1000 * 60 * 60 * 24 * 7));
    const hash = crypto.createHash("sha256").update(hwid + week).digest("hex");
    return hash.slice(0, 16); // Shorten key
}

app.get("/getkey", (req, res) => {
    const hwid = req.query.hwid;
    if (!hwid) return res.status(400).send("Missing HWID");

    const key = generateKey(hwid);
    res.send(key);
});

app.listen(port, () => {
    console.log(`Key server running on port ${port}`);
});
