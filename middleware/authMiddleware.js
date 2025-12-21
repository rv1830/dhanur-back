import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import User from '../models/User.js';

// =================================================================
// 🍪 COOKIE OPTIONS
// =================================================================
export const cookieOptions = {
    httpOnly: true,
    secure: true,      // Hamesha TRUE (Kyunki backend Render par HTTPS hai)
    sameSite: 'none',  // Hamesha NONE (Kyunki Localhost -> Render cross-site hai)
    maxAge: 30 * 24 * 60 * 60 * 1000,
    path: '/',
};

console.log('🍪 Cookie Options:', {
    httpOnly: cookieOptions.httpOnly,
    secure: cookieOptions.secure,
    sameSite: cookieOptions.sameSite,
    environment: process.env.NODE_ENV || 'development'
});

// =================================================================
// 🔒 PROTECT MIDDLEWARE (UPDATED FOR UID)
// =================================================================
export const protect = asyncHandler(async (req, res, next) => {
    console.log('\n=== 🔐 AUTH CHECK START ===');
    console.log('📍 Route:', req.method, req.originalUrl);
    console.log('🍪 Cookies:', req.cookies);
    console.log('📋 Auth Header:', req.headers.authorization || 'None');
    
    let token;

    // 1. Check cookie
    if (req.cookies && req.cookies.token) {
        token = req.cookies.token;
        console.log('✅ Token found in COOKIE');
    }
    // 2. Check Authorization header
    else if (req.headers.authorization?.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
        console.log('✅ Token found in BEARER HEADER');
    }

    if (!token) {
        console.error('❌ NO TOKEN FOUND');
        console.log('=== 🔐 AUTH CHECK END (FAILED) ===\n');
        res.status(401);
        throw new Error('Not authorized, no token provided.');
    }

    try {
        console.log('🔍 Verifying JWT...');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        console.log('✅ JWT decoded:', decoded);
        
        // 🚨 INDUSTRY FIX: 'decoded.id' mein ab hamara 'uid' (US-...) aayega
        const publicId = decoded.userId || decoded.id;
        
        if (!publicId) {
            console.error('❌ No publicId (uid) in token');
            res.status(401);
            throw new Error('Invalid token format.');
        }

        console.log('🔍 Finding user by UID:', publicId);
        // MongoDB _id ke bajaye UID se search kar rahe hain
        const user = await User.findOne({ uid: publicId }).select('-password');

        if (!user) {
            console.error(`❌ User not found with UID: ${publicId}`);
            res.status(401);
            throw new Error('User not found.');
        }

        // Check token version
        if (decoded.tokenVersion !== undefined && decoded.tokenVersion !== user.tokenVersion) {
            console.warn(`⚠️ Token version mismatch! Token: ${decoded.tokenVersion}, DB: ${user.tokenVersion}`);
            res.clearCookie('token', cookieOptions);
            res.status(401);
            throw new Error('Session expired. Please log in again.');
        }

        req.user = user;
        console.log('✅ User authenticated:', user.email || user.phoneNumber || user.uid);
        console.log('=== 🔐 AUTH CHECK END (SUCCESS) ===\n');
        next();

    } catch (error) {
        console.error('❌ Auth failed:', error.message);
        console.log('=== 🔐 AUTH CHECK END (FAILED) ===\n');
        res.clearCookie('token', cookieOptions);
        res.status(401);
        throw new Error('Not authorized, token failed or expired.');
    }
});

// =================================================================
// 🚫 ERROR HANDLERS
// =================================================================
export const notFound = (req, res, next) => {
    const error = new Error(`Not Found - ${req.originalUrl}`);
    console.error(`❌ 404: ${req.originalUrl}`);
    res.status(404);
    next(error);
};

export const errorHandler = (err, req, res, next) => {
    const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
    
    if (statusCode >= 500 || statusCode === 401) {
        console.error(`❌ ERROR ${statusCode}:`, err.message);
        if (process.env.NODE_ENV !== 'production') {
            console.error('Stack:', err.stack);
        }
    }
    
    res.status(statusCode).json({
        message: err.message,
        stack: process.env.NODE_ENV === 'production' ? null : err.stack,
    });
};

// =================================================================
// 🛡️ ROLE-BASED ACCESS CONTROL (RBAC)
// =================================================================

// 1. Brand ya Member dono access kar payein
export const isBrand = asyncHandler(async (req, res, next) => {
    const allowedBrandRoles = ['BRAND', 'MEMBER'];
    
    // User logged in hai aur uska type BRAND ya MEMBER hai
    if (req.user && allowedBrandRoles.includes(req.user.userType)) {
        console.log(`✅ Access Granted: Verified ${req.user.userType}`);
        next();
    } else {
        res.status(403); 
        throw new Error('Access denied. Brand account required.');
    }
});

// 2. Sirf Influencer hi access kar paye
export const isInfluencer = asyncHandler(async (req, res, next) => {
    if (req.user && req.user.userType === 'INFLUENCER' && req.user.onboardingComplete) {
        console.log(`✅ Access Granted: User is a verified INFLUENCER`);
        next();
    } else {
        console.error(`❌ Access Denied: User is not an INFLUENCER`);
        res.status(403);
        throw new Error('Access denied. This area is reserved for Influencers.');
    }
});

export const canSetupProfile = asyncHandler(async (req, res, next) => {
    if (req.user && !req.user.profileComplete) {
        next();
    } else {
        res.status(400);
        throw new Error('Profile already completed.');
    }
});

export const canSelectUserType = asyncHandler(async (req, res, next) => {
    if (req.user && req.user.profileComplete && !req.user.userType) {
        next();
    } else {
        res.status(400);
        throw new Error('User type already selected or profile incomplete.');
    }
});