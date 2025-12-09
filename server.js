// server.js
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors'; 
import connectDB from './config/db.js';
import socialRoutes from './routes/socialRoutes.js';
import userRoutes from './routes/userRoutes.js'; 
import { notFound, errorHandler } from './middleware/authMiddleware.js'; 

// --- SSL Fix Imports ---
import axios from 'axios';
import https from 'https';
// -----------------------

dotenv.config();
connectDB(); // Connect to MongoDB

// =============================================================
// 🛠️ FIX: DEVELOPMENT SSL/TLS ERROR (FOR LINKEDIN, AXIOS)
// =============================================================
// Note: This is for development/debugging only. 
// It prevents the 'AggregateError' when Node.js can't verify 
// the HTTPS certificate of external services like LinkedIn.
const httpsAgent = new https.Agent({
    rejectUnauthorized: false,
});
axios.defaults.httpsAgent = httpsAgent;
// =============================================================


const app = express();

// --- CORS Configuration (Fix for frontend) ---
const allowedOrigins = [
    'http://localhost:3000', // Your Next.js Frontend URL
];

const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) return callback(null, true); 
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS')); 
        }
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', 
    credentials: true,
    optionsSuccessStatus: 204
};

app.use(cors(corsOptions)); 

app.use(express.json()); // Body parser

// --- Routes ---
app.use('/api/users', userRoutes); // New: User Authentication Routes
app.use('/api/social', socialRoutes);

app.get('/', (req, res) => {
    res.send('Dhanur Backend is Running (ESM)!');
});

// --- Error Handling Middleware ---
app.use(notFound);
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});