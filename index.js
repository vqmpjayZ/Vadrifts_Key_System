const express = require("express");
const crypto = require("crypto");
const cors = require("cors");
const path = require("path");

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.static("public"));

const activeSlugs = new Map();

function generateKey(hwid) {
    const week = Math.floor(Date.now() / (1000 * 60 * 60 * 24 * 7));
    const hash = crypto.createHash("sha256").update(hwid + week).digest("hex");
    return hash.slice(0, 16);
}

function createSlug(hwid) {
    const slug = Math.random().toString(36).substring(2, 9);
    activeSlugs.set(slug, hwid);
    setTimeout(() => {
        activeSlugs.delete(slug);
    }, 5 * 60 * 1000);
    return slug;
}

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/create", (req, res) => {
    const hwid = req.query.hwid;
    if (!hwid) return res.status(400).send("Missing HWID");
    const slug = createSlug(hwid);
    res.send(`https://${req.headers.host}/getkey/${slug}`);
});

app.get("/getkey/:slug", (req, res) => {
    const slug = req.params.slug;
    const hwid = activeSlugs.get(slug);
    if (!hwid) return res.status(404).send("Invalid or expired key link");
    activeSlugs.delete(slug);
    const key = generateKey(hwid);
    res.send(key);
});

app.get("/verify", (req, res) => {
    const selectedSystem = req.query.system;
    res.sendFile(path.join(__dirname, "public", "verify.html"));
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
