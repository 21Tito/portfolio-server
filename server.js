const express = require('express');
const { MongoClient } = require('mongodb');
const cors = require('cors');
require('dotenv').config();

const app = express();

// CORS configuration
app.use(cors({
    origin: 'https://21tito.github.io',
    methods: ['POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.json());

// MongoDB connection
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri);

// Contact form endpoint
app.post('/api/contact', async (req, res) => {
    try {
        await client.connect();
        const collection = client.db('portfolio').collection('contacts');
        
        const submission = {
            name: req.body.name,
            email: req.body.email,
            message: req.body.message,
            date: new Date()
        };
        
        await collection.insertOne(submission);
        res.json({ success: true, message: 'Message sent successfully!' });
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).json({ success: false, message: 'Error sending message' });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 