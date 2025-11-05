// index.js
require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const fetch = require('node-fetch');

// --- INITIALIZE FIREBASE ADMIN ---
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

// --- INITIALIZE EXPRESS APP ---
const app = express();
app.use(cors()); // Allow requests from any origin
app.use(express.json()); // To parse JSON request bodies

// --- API KEY AUTHENTICATION MIDDLEWARE ---
const authenticateApiKey = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ error: 'Unauthorized: No API key provided.' });
  }
  const apiKey = authHeader.split('Bearer ')[1];
  
  try {
    const usersRef = db.collection('users');
    const snapshot = await usersRef.where('apiKey', '==', apiKey).limit(1).get();

    if (snapshot.empty) {
      return res.status(403).send({ error: 'Forbidden: Invalid API key.' });
    }

    const userDoc = snapshot.docs[0];
    req.user = { uid: userDoc.id, ...userDoc.data() }; // Attach user data to the request object
    
    if (req.user.status === 'banned') {
        return res.status(403).send({ error: 'Forbidden: This account has been suspended.' });
    }

    next();
  } catch (error) {
    console.error('Error during API key authentication:', error);
    res.status(500).send({ error: 'Internal server error.' });
  }
};

// --- ADMIN-ONLY AUTHENTICATION MIDDLEWARE ---
const authenticateAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== 'admin') {
        return res.status(403).send({ error: 'Forbidden: Admin access required.' });
    }
    next();
};


// --- API ENDPOINTS ---

// Health check route
app.get('/', (req, res) => {
    res.send('Zohosmsgh Developer API is running!');
});

/**
 * GET /api/balance
 * Checks the user's current coin balance.
 */
app.get('/api/balance', authenticateApiKey, (req, res) => {
    res.status(200).send({ 
        balance: req.user.balance,
        firstName: req.user.firstName
    });
});

/**
 * POST /api/sender-ids/request
 * Registers a new Sender ID for the user.
 */
app.post('/api/sender-ids/request', authenticateApiKey, async (req, res) => {
    const { senderId, companyName, purpose } = req.body;
    const uid = req.user.uid;

    if (!senderId || !companyName || !purpose) {
        return res.status(400).send({ error: 'Missing required fields: senderId, companyName, purpose.' });
    }
    if (senderId.length < 4 || senderId.length > 11) {
        return res.status(400).send({ error: 'Sender ID must be between 4 and 11 characters.' });
    }

    try {
        const newSenderIdRef = db.collection('senderIds').doc();
        await newSenderIdRef.set({
            senderId,
            companyName,
            purpose,
            userId: uid,
            status: 'Pending',
            date: new Date().toISOString()
        });
        res.status(201).send({ success: true, message: 'Sender ID request submitted successfully.' });
    } catch (error) {
        console.error('Error requesting sender ID:', error);
        res.status(500).send({ error: 'Failed to submit Sender ID request.' });
    }
});

/**
 * POST /api/send-sms
 * Sends a single or bulk SMS via sms.aigh.dev provider.
 */
app.post('/api/send-sms', authenticateApiKey, async (req, res) => {
    const { to, from, message } = req.body;
    const uid = req.user.uid;
    console.log([${new Date().toISOString()}] Received SMS request from user ${uid}. To: ${JSON.stringify(to)}, From: ${from});

    if (!to || !from || !message) {
        console.log(" > Validation failed: Missing required fields.");
        return res.status(400).send({ error: 'Missing required fields: to, from, message.' });
    }

    const userRef = db.collection('users').doc(uid);
    const parts = message.length > 160 ? Math.ceil(message.length / 153) : 1;
    const recipients = Array.isArray(to) ? to : [to];
    const cost = recipients.length * parts * 1.5;

    try {
        // Step 1: Verify Sender ID is approved for user
        console.log(` > Verifying sender ID '${from}' for user ${uid}...`);
        const senderIdSnapshot = await db.collection('senderIds').where('userId', '==', uid).where('senderId', '==', from).where('status', '==', 'Approved').get();
        if (senderIdSnapshot.empty) {
            console.log(` > Verification failed: Sender ID '${from}' is not approved.`);
            return res.status(403).send({ error: Forbidden: Sender ID '${from}' is not approved for your account. });
        }
        console.log(` > Sender ID '${from}' is approved.`);

        // Step 2: Read user data, check balance, and get system settings
        const userDoc = await userRef.get();
        if (!userDoc.exists) {
            return res.status(404).send({ error: 'User not found' });
        }
        const userData = userDoc.data();
        const currentBalance = userData.balance;
        console.log(` > Current user balance: ${currentBalance} coins. Required: ${cost} coins.`);

        if (currentBalance < cost) {
            console.log(` > Error: Insufficient funds.`);
            return res.status(402).send({ success: false, code: 'INSUFFICIENT_FUNDS', message: 'Insufficient coin balance.' });
        }
        
        const settingsDoc = await db.collection('system').doc('settings').get();
        if (!settingsDoc.exists) {
             return res.status(500).send({ error: 'System settings not configured.' });
        }
        const settings = settingsDoc.data();
        const apiKey = settings.aighSmsApiKey;

        if (!apiKey) {
            console.log(` > Error: SMS Gateway API Key is not configured in admin settings.`);
            return res.status(503).send({ code: 'GATEWAY_UNCONFIGURED', message: 'The SMS gateway is not configured. Please contact support.' });
        }

        // Step 3: Make the external API call to aigh.dev
        const isBulk = recipients.length > 1;
        const endpoint = isBulk ? 'send-bulk' : 'send';
        const url = https://sms.aigh.dev/api/v1/sms/${endpoint};
        
        const payload = {
            senderId: from,
            message: message,
        };

        if (isBulk) {
            payload.recipients = recipients;
        } else {
            payload.recipient = recipients[0];
            payload.ref = zohosms_${uid}_${Date.now()};
        }

        console.log(` > Calling SMS provider at ${url}...`);
        const smsResponse = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': Bearer ${apiKey},
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
        });
        
        const responseJson = await smsResponse.json();
        console.log(` > SMS provider response status: ${smsResponse.status}, body: ${JSON.stringify(responseJson)}`);

        if (!smsResponse.ok) {
            console.error(" > SMS Provider Error:", responseJson.message || responseJson);
            return res.status(502).send({ success: false, code: 'PROVIDER_ERROR', message: SMS provider error: ${responseJson.message || 'Unknown error'} });
        }
        console.log(" > SMS provider call successful.");

        // Step 4: Perform atomic Firestore updates
        await db.runTransaction(async (transaction) => {
            const freshUserDoc = await transaction.get(userRef);
            if (freshUserDoc.data().balance < cost) {
                console.error(CRITICAL: Insufficient funds for user ${uid} detected after sending SMS. SMS sent but NOT charged.);
                throw new Error("INSUFFICIENT_FUNDS_RACE_CONDITION");
            }
            
            transaction.update(userRef, { 
                balance: admin.firestore.FieldValue.increment(-cost),
                firstMessageSent: true 
            });
            
            const batchId = api_batch_${Date.now()};
            recipients.forEach(recipient => {
                const historyRef = db.collection('smsHistory').doc();
                transaction.set(historyRef, {
                    userId: uid, to: recipient, message, senderId: from, parts,
                    date: new Date().toISOString(), status: 'Sent',
                    type: isBulk ? 'bulk' : 'single', batchId,
                });
            });
        });

        // Step 5: Handle referral commission
        if (userData.referredBy && !userData.firstMessageSent) {
            console.log(` > Handling first-message referral commission for referrer ${userData.referredBy}.`);
            const referrerRef = db.collection('users').doc(userData.referredBy);
            await referrerRef.update({
                referralBalance: admin.firestore.FieldValue.increment(1.00),
                referralEarnings: admin.firestore.FieldValue.increment(1.00)
            }).catch(err => console.error(" > Failed to award referral commission:", err));
        }

        console.log(" > Firestore updates successful.");
        res.status(200).send({ success: true, message: 'Messages sent successfully.' });

    } catch (error) {
        console.error('CRITICAL ERROR in /api/send-sms:', error.message);
        if (error.message === 'INSUFFICIENT_FUNDS_RACE_CONDITION') {
             res.status(500).send({ success: false, code: 'BILLING_ERROR', message: 'SMS was sent, but we detected an issue with your balance. Please contact support.' });
        } else {
             res.status(500).send({ success: false, code: 'INTERNAL_ERROR', message: 'SMS may have been sent, but an internal error occurred. Please check your SMS history and balance, and contact support if there is a discrepancy.' });
        }
    }
});


/**
 * POST /api/admin/send-system-sms
 * Sends an SMS from the system using the aigh.dev provider. Admin only.
 */
app.post('/api/admin/send-system-sms', authenticateApiKey, authenticateAdmin, async (req, res) => {
    const { to, message } = req.body;

    if (!to || !message) {
        return res.status(400).send({ error: 'Missing required fields: to, message.' });
    }

    try {
        const settingsDoc = await db.collection('system').doc('settings').get();
        if (!settingsDoc.exists) {
            return res.status(500).send({ error: 'System settings not found.' });
        }
        const settings = settingsDoc.data();
        const apiKey = settings.aighSmsApiKey;
        const senderId = settings.aighSmsSenderId;

        if (!apiKey || !senderId) {
            return res.status(500).send({ error: 'SMS Gateway is not configured in admin settings.' });
        }

        const url = 'https://sms.aigh.dev/api/v1/sms/send';
        const payload = {
            senderId,
            recipient: to,
            message,
            ref: zohosms_system_${Date.now()}
        };

        const smsResponse = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': Bearer ${apiKey},
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        const responseJson = await smsResponse.json();

        if (!smsResponse.ok) {
            console.error("System SMS Provider Error:", responseJson);
            throw new Error('PROVIDER_ERROR');
        }

        res.status(200).send({ success: true, message: 'System message sent successfully.' });

    } catch (error) {
        console.error('Error sending system SMS:', error.message);
        res.status(500).send({ success: false, message: 'An internal server error occurred while sending the system SMS.' });
    }
});


// --- START THE SERVER ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(Server is running on port ${PORT});
});
