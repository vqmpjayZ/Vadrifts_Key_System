const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware boii
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// In-memory storage (use Redis/MongoDB for production)
const keys = new Map();
const userSessions = new Map();

// Secret key for HMAC (use environment variable in production)
const SECRET_KEY = process.env.SECRET_KEY || 'your-super-secret-key-change-this';

// Generate unique key for user
function generateKey(userId, timestamp) {
  const data = `${userId}-${timestamp}-${Date.now()}`;
  return crypto.createHmac('sha256', SECRET_KEY)
    .update(data)
    .digest('hex')
    .substring(0, 32);
}

// Generate user session ID
function generateSession() {
  return crypto.randomBytes(32).toString('hex');
}

// Verify key integrity
function verifyKey(key, userId, timestamp) {
  const expectedKey = crypto.createHmac('sha256', SECRET_KEY)
    .update(`${userId}-${timestamp}`)
    .digest('hex')
    .substring(0, 32);
  return crypto.timingSafeEqual(Buffer.from(key), Buffer.from(expectedKey));
}

// Universal key page that works for any user
app.get('/getkey', (req, res) => {
  // This will work for any user who visits
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Get Your Key</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 20px;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                text-align: center;
                max-width: 400px;
                width: 100%;
            }
            .key-box {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
                font-family: monospace;
                font-size: 14px;
                word-break: break-all;
                border: 2px dashed #dee2e6;
                display: none;
            }
            .copy-btn {
                background: #28a745;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                margin-top: 10px;
                display: none;
            }
            .copy-btn:hover {
                background: #218838;
            }
            .generate-btn {
                background: #007bff;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔑 Get Your Access Key</h1>
            <p>Complete the verification above, then generate your personal key:</p>
            
            <!-- work.ink ad goes here -->
            <div id="work-ink-ad">
                <!-- Replace this with actual work.ink code -->
                <p style="color: #666;">Complete the verification task above ↑</p>
            </div>
            
            <button class="generate-btn" onclick="generateKey()">Generate My Key</button>
            
            <div class="key-box" id="keyBox"></div>
            
            <button class="copy-btn" id="copyBtn" onclick="copyKey()">
                Copy Key
            </button>
            
            <script>
                let userKey = null;
                
                function generateKey() {
                    // Generate a random user ID (or use Roblox user ID if available)
                    const userId = 'user_' + Math.random().toString(36).substr(2, 9);
                    
                    fetch('/api/generate-universal-key', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({ userId: userId })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.key) {
                            userKey = data.key;
                            document.getElementById('keyBox').textContent = userKey;
                            document.getElementById('keyBox').style.display = 'block';
                            document.getElementById('copyBtn').style.display = 'inline-block';
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('Failed to generate key. Try again.');
                    });
                }
                
                function copyKey() {
                    if (userKey) {
                        navigator.clipboard.writeText(userKey).then(() => {
                            const btn = document.getElementById('copyBtn');
                            btn.textContent = 'Copied!';
                            btn.style.background = '#17a2b8';
                            setTimeout(() => {
                                btn.textContent = 'Copy Key';
                                btn.style.background = '#28a745';
                            }, 2000);
                        });
                    }
                }
            </script>
        </div>
    </body>
    </html>
  `;
  
  res.send(html);
});

// API endpoint for universal key generation
app.post('/api/generate-universal-key', (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID required' });
    }

    const timestamp = Date.now();
    const key = generateKey(userId, timestamp);
    
    const keyData = {
      key,
      userId,
      timestamp,
      expires: timestamp + (24 * 60 * 60 * 1000),
      used: false
    };
    
    keys.set(key, keyData);

    res.json({
      key: key,
      expiresIn: 24 * 60 * 60 * 1000
    });
    
  } catch (error) {
    console.error('Universal key generation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get key page (for work.ink integration)
app.get('/key/:sessionId', (req, res) => {
  const { sessionId } = req.params;
  const session = userSessions.get(sessionId);
  
  if (!session) {
    return res.status(404).send('Invalid session');
  }

  // Find the key for this session
  let userKey = null;
  for (const [key, data] of keys.entries()) {
    if (data.userId === session.userId && !data.used && data.expires > Date.now()) {
      userKey = key;
      break;
    }
  }

  if (!userKey) {
    return res.status(404).send('No valid key found');
  }

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Get Your Key</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 20px;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
                text-align: center;
                max-width: 400px;
                width: 100%;
            }
            .key-box {
                background: #f8f9fa;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
                font-family: monospace;
                font-size: 14px;
                word-break: break-all;
                border: 2px dashed #dee2e6;
            }
            .copy-btn {
                background: #28a745;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                cursor: pointer;
                margin-top: 10px;
            }
            .copy-btn:hover {
                background: #218838;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔑 Your Access Key</h1>
            <p>Complete the verification below, then copy your key:</p>
            
            <!-- work.ink ad integration -->
            <div id="work-ink-ad">
                <!-- This is where you'd integrate work.ink -->
                <p style="color: #666;">Complete the verification task above ↑</p>
            </div>
            
            <div class="key-box" id="keyBox" style="display: none;">
                ${userKey}
            </div>
            
            <button class="copy-btn" id="copyBtn" onclick="copyKey()" style="display: none;">
                Copy Key
            </button>
            
            <script>
                // Simulate work.ink completion (replace with actual work.ink code)
                setTimeout(() => {
                    document.getElementById('keyBox').style.display = 'block';
                    document.getElementById('copyBtn').style.display = 'inline-block';
                    document.getElementById('work-ink-ad').innerHTML = '<p style="color: green;">✅ Verification Complete!</p>';
                }, 3000);
                
                function copyKey() {
                    const keyText = document.getElementById('keyBox').textContent;
                    navigator.clipboard.writeText(keyText).then(() => {
                        const btn = document.getElementById('copyBtn');
                        btn.textContent = 'Copied!';
                        btn.style.background = '#17a2b8';
                        setTimeout(() => {
                            btn.textContent = 'Copy Key';
                            btn.style.background = '#28a745';
                        }, 2000);
                    });
                }
            </script>
        </div>
    </body>
    </html>
  `;
  
  res.send(html);
});

// Verify key endpoint (called from Roblox)
app.post('/api/verify-key', (req, res) => {
  try {
    const { key, userId } = req.body;
    
    if (!key || !userId) {
      return res.status(400).json({ 
        success: false, 
        error: 'Key and User ID required' 
      });
    }

    const keyData = keys.get(key);
    
    if (!keyData) {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid key' 
      });
    }

    // Check if key is expired
    if (keyData.expires < Date.now()) {
      keys.delete(key);
      return res.status(401).json({ 
        success: false, 
        error: 'Key expired' 
      });
    }

    // Check if key belongs to user
    if (keyData.userId !== userId) {
      return res.status(401).json({ 
        success: false, 
        error: 'Key does not belong to user' 
      });
    }

    // Check if key already used
    if (keyData.used) {
      return res.status(401).json({ 
        success: false, 
        error: 'Key already used' 
      });
    }

    // Mark key as used
    keyData.used = true;
    keys.set(key, keyData);

    res.json({ 
      success: true, 
      message: 'Key verified successfully',
      userId: keyData.userId
    });

  } catch (error) {
    console.error('Key verification error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error' 
    });
  }
});

// Cleanup function for expired keys
function cleanupExpiredKeys() {
  const now = Date.now();
  for (const [key, data] of keys.entries()) {
    if (data.expires < now) {
      keys.delete(key);
    }
  }
}

setInterval(cleanupExpiredKeys, 60 * 60 * 1000);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: Date.now() });
});

app.listen(PORT, () => {
  console.log(`Key system server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});
