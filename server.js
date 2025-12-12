// server.js
import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import connectDB from './config/db.js';
import socialRoutes from './routes/socialRoutes.js';
import authRoutes from './routes/authRoutes.js'; // 👈 CENTRALIZED AUTH

// Middleware
import { notFound, errorHandler } from './middleware/authMiddleware.js'; 
// import protect from './middleware/protectRoute.js'; // 👈 DELETED/MERGED

// SSL Fix for Dev (LinkedIn, Google OAuth callbacks)
import axios from 'axios';
import https from 'https';
const httpsAgent = new https.Agent({ rejectUnauthorized: false });
axios.defaults.httpsAgent = httpsAgent;

dotenv.config();
connectDB();

const app = express();

// =============================================================
// SECURITY & PERFORMANCE MIDDLEWARES
// =============================================================

app.use(helmet({
    contentSecurityPolicy: false, 
}));

// Cookie Parser — HTTP-only cookies ke liye zaroori
app.use(cookieParser());

// Body Parser
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate Limiting
const limiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutes
    max: 100, 
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', limiter); 

// CORS
const isProduction = process.env.NODE_ENV === 'production';
const corsOptions = {
    origin: isProduction 
        ? ['https://dhanur.app', 'https://www.dhanur.app'] 
        : ['http://localhost:3000', 'http://localhost:3001'], 
    credentials: true, // Cookies bhejne ke liye zaroori
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};
app.use(cors(corsOptions));

// =============================================================
// ROUTES
// =============================================================

// Public & Protected Auth Routes (Email/Pass, Social, OTP, Logout)
// Note: /api/users route is now obsolete. All login/register routes are under /api/auth
app.use('/api/auth', authRoutes);      

// Social Connect + Sync (Keep if these are separate from initial auth)
app.use('/api/social', socialRoutes);  

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Dhanur Backend is LIVE!', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
    res.json({ 
        message: 'Welcome to Dhanur API', 
        version: '2.0', 
        docs: '/api/health' 
    });
});

// =============================================================
// ERROR HANDLING (Last mein hona chahiye)
// =============================================================
app.use(notFound);
app.use(errorHandler);

// =============================================================
// SERVER START
// =============================================================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`\n Dhanur Backend Running`);
    console.log(` Mode: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
    console.log(` Server: http://localhost:${PORT}`);
    console.log(` Health: http://localhost:${PORT}/api/health\n`);
});