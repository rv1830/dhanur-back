// server.js (UPDATED with node-cron setup)

import express from 'express';
import dotenv from 'dotenv';
import path from 'path'; 
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import connectDB from './config/db.js';
import socialRoutes from './routes/socialRoutes.js';
import authRoutes from './routes/authRoutes.js'; 
import chalk from 'chalk';
import cron from 'node-cron'; // 👈 NEW: cron library import करें
import { runDailyYoutubeSync } from './services/youtubeService.js'; // 👈 NEW: Sync service import करें

// Middleware
import { notFound, errorHandler } from './middleware/authMiddleware.js'; 

// SSL Fix for Dev (LinkedIn, Google OAuth callbacks)
import axios from 'axios';
import https from 'https';
const httpsAgent = new https.Agent({ rejectUnauthorized: false });
axios.defaults.httpsAgent = httpsAgent;


const env = process.env.NODE_ENV || 'development'; 
dotenv.config({ path: path.resolve(process.cwd(), `.env.${env}`) });

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
// const limiter = rateLimit({
// 	windowMs: 10 * 60 * 1000, // 10 minutes
// 	max: 100, 
// 	message: { error: 'Too many requests, please try again later.' },
// 	standardHeaders: true,
// 	legacyHeaders: false,
// });
// app.use('/api/', limiter); 

// CORS
const isProduction = process.env.NODE_ENV === 'production';
const corsOptions = {
    origin: isProduction 
        ? ['https://dhanur.app', 'https://www.dhanur.app', 'https://dhanur-collab.vercel.app'] 
        : ['http://localhost:3000', 'http://localhost:3001'], 
    credentials: true, // Cookies bhejne ke liye zaroori
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};
app.use(cors(corsOptions));


app.use('/api/auth', authRoutes);       

// Social Connect + Sync 
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
// ⏰ NEW: CRON JOB SCHEDULER SETUP
// =============================================================

const setupCronJobs = () => {
    // हर दिन सुबह 2:00 बजे (02:00) पर Sync चलाएं।
    // Cron Format: [second] [minute] [hour] [day of month] [month] [day of week]
    
    // आप यहाँ अपने टाइमज़ोन के अनुसार समय बदल सकते हैं।
    cron.schedule('0 0 2 * * *', async () => {
        console.log('--- [CRON] Running scheduled daily YouTube data sync (2:00 AM) ---');
        try {
            await runDailyYoutubeSync();
            console.log('--- [CRON] YouTube Sync finished successfully. ---');
        } catch (error) {
            console.error('--- [CRON] CRITICAL FAILURE in YouTube Sync Job ---', error.message);
        }
    }, {
        scheduled: true,
        timezone: "Asia/Kolkata" // 👉 इसे अपनी टाइम ज़ोन में बदल लें
    });
    
    console.log('✅ Daily YouTube Sync Cron Job scheduled for 2:00 AM.');
};


// =============================================================
// ENHANCED SERVER START LOG
// =============================================================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    const modeText = isProduction ? chalk.green.bold('PRODUCTION') : chalk.yellow.bold('DEVELOPMENT');
    
    console.log('============================================');
    console.log(` 🌐 Dhanur Backend Running: ${modeText}`);
    console.log(' 🟢 Server Status: LIVE!');
    console.log(` 🔗 Local URL: http://localhost:${PORT}`);
    console.log(' 🩺 Health Check: /api/health');
    console.log('============================================');

    // सर्वर शुरू होने के बाद Cron Jobs को सेट अप करें
    setupCronJobs(); // 👈 Cron Job यहाँ से शुरू होगा
});

// =============================================================
// ERROR HANDLING 
// =============================================================
app.use(notFound);
app.use(errorHandler);