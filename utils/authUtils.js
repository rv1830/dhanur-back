import jwt from 'jsonwebtoken';
import { cookieOptions } from '../middleware/authMiddleware.js'; 
import User from '../models/User.js';

export const setTokenCookie = (res, user) => {
    const token = jwt.sign(
        {
            id: user.uid, // Clean Public ID (US-1234...)
            tokenVersion: user.tokenVersion || 0,
            userType: user.userType,
            onboardingComplete: user.onboardingComplete || false,
        },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
    );

    res.cookie('token', token, cookieOptions);
};

/**
 * Increments the tokenVersion in the database, invalidating all old tokens for this user.
 * @param {string} userId - ID of the user whose session should be invalidated.
 */
export const invalidateSession = async (userId) => {
    // Find the user and increment their tokenVersion
    await User.findByIdAndUpdate(
        userId,
        { $inc: { tokenVersion: 1 } },
        { new: true } // Return the updated document
    );
    // Note: The old token will still exist on the client, but 'protect' middleware will fail it.
};