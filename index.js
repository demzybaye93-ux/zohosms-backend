// index.js
require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');

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
 * Sends a single or bulk SMS with detailed logging.
 */
app.post('/api/send-sms', authenticateApiKey, async (req, res) => {
    const { to, from, message } = req.body;
    const uid = req.user.uid;
    console.log(`[${new Date().toISOString()}] Received SMS request from user ${uid}.`);
    console.log(` > To: ${JSON.stringify(to)}, From: ${from}`);

    if (!to || !from || !message) {
        console.log(" > Validation failed: Missing required fields.");
        return res.status(400).send({ error: 'Missing required fields: to, from, message.' });
    }

    console.log(` > Verifying sender ID '${from}' for user ${uid}...`);
    const senderIdRef = db.collection('senderIds');
    const senderIdSnapshot = await senderIdRef.where('userId', '==', uid).where('senderId', '==', from).where('status', '==', 'Approved').get();
    if (senderIdSnapshot.empty) {
        console.log(` > Verification failed: Sender ID '${from}' is not approved.`);
        return res.status(403).send({ error: `Forbidden: Sender ID '${from}' is not approved for your account.` });
    }
    console.log(` > Sender ID '${from}' is approved.`);

    const parts = message.length > 160 ? Math.ceil(message.length / 153) : 1;
    const recipients = Array.isArray(to) ? to : [to];
    const cost = recipients.length * parts * 1.5;
    console.log(` > Calculated cost: ${cost} coins for ${recipients.length} recipients and ${parts} parts.`);

    const userRef = db.collection('users').doc(uid);

    try {
        await db.runTransaction(async (transaction) => {
            const userDoc = await transaction.get(userRef);
            if (!userDoc.exists) {
                console.log(` > Transaction error: User document for ${uid} not found.`);
                throw new Error('User not found');
            }

            const userData = userDoc.data();
            const currentBalance = userData.balance;
            console.log(` > Current user balance: ${currentBalance} coins.`);
            if (currentBalance < cost) {
                console.log(` > Transaction error: Insufficient funds. Balance: ${currentBalance}, Cost: ${cost}.`);
                throw new Error('INSUFFICIENT_FUNDS');
            }

            console.log(" > Preparing to call SMS gateway...");
            const apiKey = process.env.BULKSMSGH_API_KEY;
            const encodedMessage = encodeURIComponent(message);
            const smsApiUrl = `https://clientlogin.bulksmsgh.com/smsapi?key=${apiKey}&to=${recipients.join(',')}&msg=${encodedMessage}&sender_id=${from}`;
            
            console.log(` > Fetching URL (key redacted): https://clientlogin.bulksmsgh.com/smsapi?key=...&to=${recipients.join(',')}&msg=...&sender_id=${from}`);
            
            console.log(" > Calling SMS provider...");
            const smsResponse = await fetch(smsApiUrl);
            const responseText = await smsResponse.text();
            console.log(` > SMS provider response status: ${smsResponse.status}`);
            console.log(` > SMS provider response text: ${responseText}`);

            if (!smsResponse.ok || !responseText.trim().startsWith('OK')) {
                console.error(" > SMS Provider Error:", responseText.trim());
                throw new Error('PROVIDER_ERROR');
            }
            console.log(" > SMS provider call successful.");

            const updates = { 
                balance: admin.firestore.FieldValue.increment(-cost),
                firstMessageSent: true // Mark first message as sent
            };
            console.log(` > Updating user balance. New balance will be ${currentBalance - cost}.`);
            transaction.update(userRef, updates);
            
            // Handle referral commission for the first message sent
            if (userData.referredBy && !userData.firstMessageSent) {
                console.log(` > First message sent by referred user. Checking for commission for referrer ${userData.referredBy}.`);
                const referrerRef = db.collection('users').doc(userData.referredBy);
                // We need to get the referrer outside the transaction for the update
                // This is a simplified approach. A more robust solution might use a Cloud Function.
                const referrerDoc = await referrerRef.get();
                if (referrerDoc.exists()) {
                    const commission = 1.00; // e.g., GH¢1.00 bonus
                    console.log(` > Awarding GH¢${commission} commission to referrer ${userData.referredBy}.`);
                    await referrerRef.update({
                        referralBalance: admin.firestore.FieldValue.increment(commission),
                        referralEarnings: admin.firestore.FieldValue.increment(commission)
                    });
                }
            }

            const batchId = `api_batch_${Date.now()}`;
            console.log(` > Logging ${recipients.length} SMS records to history with batchId ${batchId}.`);
            recipients.forEach(recipient => {
                const historyRef = db.collection('smsHistory').doc();
                transaction.set(historyRef, {
                    userId: uid,
                    to: recipient,
                    message,
                    senderId: from,
                    parts,
                    date: new Date().toISOString(),
                    status: 'Sent',
                    type: recipients.length > 1 ? 'bulk' : 'single',
                    batchId,
                });
            });
            console.log(" > Transaction successful.");
        });

        res.status(200).send({ success: true, message: 'Messages queued for sending.' });

    } catch (error) {
        console.error('Error sending SMS:', error.message);
        if (error.message === 'INSUFFICIENT_FUNDS') {
            return res.status(402).send({ success: false, code: 'INSUFFICIENT_FUNDS', message: 'Insufficient coin balance.' });
        }
        if (error.message === 'PROVIDER_ERROR') {
             return res.status(502).send({ success: false, code: 'PROVIDER_ERROR', message: 'There was an error with the SMS provider.' });
        }
        res.status(500).send({ success: false, message: 'An internal server error occurred.' });
    }
});


/**
 * POST /api/admin/send-system-sms
 * Sends an SMS from the system using the default sender ID. Admin only.
 */
app.post('/api/admin/send-system-sms', authenticateApiKey, authenticateAdmin, async (req, res) => {
    const { to, message } = req.body;

    if (!to || !message) {
        return res.status(400).send({ error: 'Missing required fields: to, message.' });
    }
    
    const apiKey = process.env.BULKSMSGH_API_KEY;

    try {
        // Fetch system settings from Firestore
        const settingsDoc = await db.collection('system').doc('settings').get();
        if (!settingsDoc.exists) {
            return res.status(500).send({ error: 'System settings not found in Firestore.' });
        }
        const settings = settingsDoc.data();
        const senderId = settings.bulksmsghSenderId;

        if (!senderId) {
            return res.status(500).send({ error: 'System Sender ID is not configured in admin settings.' });
        }

        const encodedMessage = encodeURIComponent(message);
        const smsApiUrl = `https://clientlogin.bulksmsgh.com/smsapi?key=${apiKey}&to=${to}&msg=${encodedMessage}&sender_id=${senderId}`;

        const smsResponse = await fetch(smsApiUrl);
        const responseText = await smsResponse.text();

        if (!smsResponse.ok || !responseText.includes('OK')) {
            console.error("System SMS Provider Error:", responseText);
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
  console.log(`Server is running on port ${PORT}`);
});
