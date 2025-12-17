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
import brandRoutes from './routes/brandRoutes.js'
import chalk from 'chalk';
import cron from 'node-cron'; 
// 👇 UPDATED IMPORTS
import { runDailyYoutubeSync } from './services/youtubeService.js'; 
import { runDailyFacebookSync } from './services/facebookService.js'; 
import { runDailyInstagramSync } from './services/instagramService.js'; 

// Middleware
import { notFound, errorHandler } from './middleware/authMiddleware.js'; 

// SSL Fix for Dev (LinkedIn, Google OAuth callbacks)
import axios from 'axios';
import https from 'https';
import Brand from './models/Brand.js';
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
    ? [
        'https://dhanur.app',
        'https://www.dhanur.app',
        'https://dhanur-collab.vercel.app',
        'http://localhost:3000'   // 👈 बस यही add
      ] 
    : ['http://localhost:3000', 'http://localhost:3001'], 
  credentials: true, 
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};

app.use(cors(corsOptions));


app.use('/api/auth', authRoutes);       
app.use('/api/social', socialRoutes);
app.use('/api/brand',brandRoutes)   

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
// ⏰ NEW: CRON JOB SCHEDULER SETUP (UPDATED)
// =============================================================

const setupCronJobs = () => {
    // 1. YouTube Sync Job (सुबह 2:00 बजे)
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
        timezone: "Asia/Kolkata" 
    });
    console.log('✅ Daily YouTube Sync Cron Job scheduled for 2:00 AM.');

    // 2. Facebook Sync Job (सुबह 2:10 बजे) 
    cron.schedule('0 10 2 * * *', async () => { 
        console.log('--- [CRON] Running scheduled daily Facebook data sync (2:10 AM) ---');
        try {
            await runDailyFacebookSync(); 
            console.log('--- [CRON] Facebook Sync finished successfully. ---');
        } catch (error) {
            console.error('--- [CRON] CRITICAL FAILURE in Facebook Sync Job ---', error.message);
        }
    }, {
        scheduled: true,
        timezone: "Asia/Kolkata" 
    });
    console.log('✅ Daily Facebook Sync Cron Job scheduled for 2:10 AM.');

    // 3. Instagram Sync Job (सुबह 2:20 बजे) 
    cron.schedule('0 20 2 * * *', async () => { 
        console.log('--- [CRON] Running scheduled daily Instagram data sync (2:20 AM) ---');
        try {
            await runDailyInstagramSync(); 
            console.log('--- [CRON] Instagram Sync finished successfully. ---');
        } catch (error) {
            console.error('--- [CRON] CRITICAL FAILURE in Instagram Sync Job ---', error.message);
        }
    }, {
        scheduled: true,
        timezone: "Asia/Kolkata" 
    });
    console.log('✅ Daily Instagram Sync Cron Job scheduled for 2:20 AM.');
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
    setupCronJobs(); 
});

// =============================================================
// ERROR HANDLING 
// =============================================================
app.use(notFound);
app.use(errorHandler);