const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
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

const SECRET_KEY = process.env.SECRET_KEY || 'hi';

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

// Generate new key endpoint
app.post('/api/generate-key', (req, res) => {
  try {
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID required' });
    }

    const sessionId = generateSession();
    const timestamp = Date.now();
    const key = generateKey(userId, timestamp);
    
    // Store key with expiration (24 hours)
    const keyData = {
      key,
      userId,
      timestamp,
      expires: timestamp + (24 * 60 * 60 * 1000),
      used: false
    };
    
    keys.set(key, keyData);
    userSessions.set(sessionId, { userId, keyGenerated: true });

    // Clean up expired keys
    cleanupExpiredKeys();

    res.json({
      sessionId,
      keyUrl: `${req.protocol}://${req.get('host')}/key/${sessionId}`,
      expiresIn: 24 * 60 * 60 * 1000 // 24 hours in ms
    });
    
  } catch (error) {
    console.error('Key generation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Universal key page (work.ink destination)
app.get('/getkey', (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>🔐 Get Your Access Key</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
                position: relative;
                overflow: hidden;
            }
            
            body::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grain" width="100" height="100" patternUnits="userSpaceOnUse"><circle cx="25" cy="25" r="1" fill="white" opacity="0.05"/><circle cx="75" cy="75" r="1" fill="white" opacity="0.05"/><circle cx="50" cy="10" r="1" fill="white" opacity="0.03"/></pattern></defs><rect width="100" height="100" fill="url(%23grain)"/></svg>');
                pointer-events: none;
            }
            
            .container {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(20px);
                border: 1px solid rgba(255, 255, 255, 0.2);
                padding: 40px;
                border-radius: 24px;
                box-shadow: 
                    0 25px 50px rgba(0, 0, 0, 0.15),
                    0 0 0 1px rgba(255, 255, 255, 0.1) inset;
                text-align: center;
                max-width: 480px;
                width: 100%;
                position: relative;
                animation: slideUp 0.6s ease-out;
            }
            
            @keyframes slideUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .header {
                margin-bottom: 30px;
            }
            
            .header h1 {
                font-size: 28px;
                font-weight: 800;
                background: linear-gradient(135deg, #667eea, #764ba2);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 8px;
            }
            
            .header p {
                color: #6b7280;
                font-size: 16px;
                line-height: 1.5;
            }
            
            .steps {
                margin: 30px 0;
                text-align: left;
            }
            
            .step {
                display: flex;
                align-items: center;
                margin: 15px 0;
                padding: 15px;
                background: rgba(103, 126, 234, 0.1);
                border-radius: 12px;
                border-left: 4px solid #667eea;
            }
            
            .step-number {
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                width: 28px;
                height: 28px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                font-size: 14px;
                margin-right: 15px;
                flex-shrink: 0;
            }
            
            .step-text {
                font-size: 14px;
                color: #374151;
                font-weight: 500;
            }
            
            .work-ink-container {
                background: #f8fafc;
                border: 2px dashed #e2e8f0;
                border-radius: 16px;
                padding: 30px;
                margin: 25px 0;
                min-height: 120px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .work-ink-placeholder {
                color: #64748b;
                font-size: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .generate-section {
                margin-top: 25px;
                padding-top: 25px;
                border-top: 1px solid #e5e7eb;
            }
            
            .generate-btn {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                padding: 16px 32px;
                border-radius: 12px;
                cursor: pointer;
                font-size: 16px;
                font-weight: 600;
                

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

// Run cleanup every hour
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
