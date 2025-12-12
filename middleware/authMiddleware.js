// middleware/authMiddleware.js (WITH DEBUG LOGS)
import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import User from '../models/User.js';

// JWT Cookie Options (exported for use in controllers like logout)
export const cookieOptions = {
    httpOnly: process.env.NODE_ENV === 'production', // Production: true (More secure) | Development: false (For ease of testing)
    secure: process.env.NODE_ENV === 'production', // Production: true (Only over HTTPS) | Development: false
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000, 
};

// =================================================================
// 1. AUTH MIDDLEWARE (protect) - Cookie and Bearer-based
// =================================================================

const protect = asyncHandler(async (req, res, next) => {
    // 1. Check for token in HTTP-only cookie
    let token = req.cookies?.token;

    // 2. Fallback: Check for token in Authorization Bearer header
    if (!token && req.headers.authorization?.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
        console.log('[DEBUG-AUTH] Found token in Bearer header (Fallback).');
    }

    if (!token) {
        console.error('[DEBUG-AUTH] ERROR: No token found in cookie or header.');
        res.status(401);
        throw new Error('Not authorized, no token provided.');
    }

    try {
        console.log('[DEBUG-AUTH] Token received. Verifying JWT...');
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        console.log(`[DEBUG-AUTH] Decoded ID: ${decoded.id}, Version: ${decoded.tokenVersion}`);
        
        const user = await User.findById(decoded.id).select('-password');

        if (!user) {
            console.error(`[DEBUG-AUTH] ERROR: JWT valid but User ID ${decoded.id} not found in DB.`);
            res.status(401);
            throw new Error('User not found.');
        }
        
        // Check for token version (critical for force logout/session revocation)
        if (decoded.tokenVersion !== user.tokenVersion) {
            console.warn(`[DEBUG-AUTH] WARNING: Session revoked. JWT version (${decoded.tokenVersion}) != DB version (${user.tokenVersion}).`);
            res.clearCookie('token', cookieOptions);
            res.status(401);
            throw new Error('Session expired or revoked. Please log in again.');
        }

        req.user = user;
        console.log(`[DEBUG-AUTH] SUCCESS: User ${user.email} authenticated.`);
        next();
    } catch (error) {
        console.error('!!! CRITICAL AUTH ERROR !!! Token validation failed:', error.message);
        res.clearCookie('token', cookieOptions); 
        res.status(401); 
        throw new Error('Not authorized, token failed or expired.');
    }
});

// =================================================================
// 2. ERROR MIDDLEWARE (Global Error Handlers)
// =================================================================

/**
 * Handles 404 (Not Found) errors for invalid routes.
 */
const notFound = (req, res, next) => {
    const error = new Error(`Not Found - ${req.originalUrl}`);
    console.error(`[DEBUG-ERROR] 404 Not Found: ${req.originalUrl}`);
    res.status(404);
    next(error); 
};

/**
 * Handles all other errors.
 */
const errorHandler = (err, req, res, next) => {
    const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
    
    // Log the error stack only if it's not a generic 404/401
    if (statusCode >= 500 || statusCode === 401) {
        console.error(`[DEBUG-ERROR] RESPONSE ${statusCode}: ${err.message}`);
        console.error(`[DEBUG-ERROR] STACK: ${err.stack}`);
    }
    
    res.status(statusCode);
    
    res.json({
        message: err.message,
        stack: process.env.NODE_ENV === 'production' ? null : err.stack,
    });
};

export { protect, notFound, errorHandler};