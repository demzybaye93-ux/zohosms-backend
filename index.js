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
 * Sends a single or bulk SMS.
 */
app.post('/api/send-sms', authenticateApiKey, async (req, res) => {
    const { to, from, message } = req.body; // `to` can be a string or an array of strings
    const uid = req.user.uid;
    
    if (!to || !from || !message) {
        return res.status(400).send({ error: 'Missing required fields: to, from, message.' });
    }
    
    // Check if user is allowed to use this senderId
    const senderIdRef = db.collection('senderIds');
    const senderIdSnapshot = await senderIdRef.where('userId', '==', uid).where('senderId', '==', from).where('status', '==', 'Approved').get();
    if (senderIdSnapshot.empty) {
        return res.status(403).send({ error: `Forbidden: Sender ID '${from}' is not approved for your account.` });
    }

    // Determine message parts (simplified logic)
    const parts = message.length > 160 ? Math.ceil(message.length / 153) : 1;
    const recipients = Array.isArray(to) ? to : [to];
    const cost = recipients.length * parts * 1.5;

    const userRef = db.collection('users').doc(uid);

    try {
        await db.runTransaction(async (transaction) => {
            const userDoc = await transaction.get(userRef);
            if (!userDoc.exists) {
                throw new Error('User not found');
            }

            const currentBalance = userDoc.data().balance;
            if (currentBalance < cost) {
                throw new Error('INSUFFICIENT_FUNDS');
            }

            // --- SMS Gateway API Call ---
            // This is where you call the actual SMS gateway from your server
            const apiKey = process.env.BULKSMSGH_API_KEY;
            const encodedMessage = encodeURIComponent(message);
            const smsApiUrl = `https://clientlogin.bulksmsgh.com/smsapi?key=${apiKey}&to=${recipients.join(',')}&msg=${encodedMessage}&sender_id=${from}`;
            
            // Using fetch requires Node.js v18+. For older versions, use a library like 'axios' or 'node-fetch'.
            const smsResponse = await fetch(smsApiUrl);
            const responseText = await smsResponse.text();

            if (!smsResponse.ok || !responseText.includes('OK')) {
                console.error("SMS Provider Error:", responseText);
                throw new Error('PROVIDER_ERROR');
            }
            // --- End of SMS Gateway Call ---

            // Update user's balance and log SMS history
            transaction.update(userRef, { balance: admin.firestore.FieldValue.increment(-cost) });
            
            const batchId = `api_batch_${Date.now()}`;
            recipients.forEach(recipient => {
                const historyRef = db.collection('smsHistory').doc();
                transaction.set(historyRef, {
                    userId: uid,
                    to: recipient,
                    message,
                    senderId: from,
                    parts,
                    date: new Date().toISOString(),
                    status: 'Sent', // You might get this from the provider's response
                    type: recipients.length > 1 ? 'bulk' : 'single',
                    batchId,
                });
            });
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


// --- START THE SERVER ---
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
