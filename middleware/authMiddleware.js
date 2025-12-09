// middleware/authMiddleware.js
import jwt from 'jsonwebtoken';
import asyncHandler from 'express-async-handler';
import User from '../models/User.js'; 

// =================================================================
// 1. AUTH MIDDLEWARE (protect)
// =================================================================

/**
 * Validates the JWT token and authenticates the user.
 * It populates req.user with the user document found in the database.
 */
const protect = asyncHandler(async (req, res, next) => {
    let token;

    // Check if the Authorization header exists and starts with 'Bearer'
    if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ) {
        try {
            // Get token from header (removes 'Bearer ')
            token = req.headers.authorization.split(' ')[1];

            // Verify token and decode the payload (which contains the user ID)
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            // Find the user by ID and attach the user object to the request (excluding password)
            req.user = await User.findById(decoded.id).select('-password');

            if (!req.user) {
                // If token is valid but user no longer exists
                res.status(401);
                throw new Error('User not found.');
            }

            // Continue to the next middleware or route handler
            next();

        } catch (error) {
            console.error('Token validation failed:', error);
            res.status(401); // Unauthorized
            throw new Error('Not authorized, token failed or expired.');
        }
    }

    // If no token is provided in the header
    if (!token) {
        res.status(401); // Unauthorized
        throw new Error('Not authorized, no token provided.');
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
    res.status(404);
    next(error); // Pass the error to the next error handler
};

/**
 * Handles all other errors (including Mongoose errors, server errors, etc.).
 * Sends a standardized JSON error response to the client.
 */
const errorHandler = (err, req, res, next) => {
    // Determine the status code (default to 500 if the status is still 200)
    const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
    
    res.status(statusCode);
    
    res.json({
        message: err.message,
        // Send stack trace only if not in production environment
        stack: process.env.NODE_ENV === 'production' ? null : err.stack,
    });
    
    // Call next() if you have more middleware, but typically this is the last
    if (next) next(err); // Optional: propagate if needed
};

export { protect, notFound, errorHandler };