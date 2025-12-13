// utils/authUtils.js
import jwt from 'jsonwebtoken';
import { cookieOptions } from '../middleware/authMiddleware.js'; 
import User from '../models/User.js'; // To access the User model for session invalidation

/**
 * Creates a JWT and sets it as an HTTP-only cookie on the response.
 * @param {object} res - Express response object.
 * @param {object} user - User document object (must have _id and tokenVersion).
 */
export const setTokenCookie = (res, user) => {
    // Payload should include user details and tokenVersion for revocation check
    const token = jwt.sign(
        {
            id: user._id,
            tokenVersion: user.tokenVersion || 0,
            // Include userType and onboardingComplete status in payload to avoid unnecessary DB lookups 
            // in some frontend logic (though 'protect' still does the main DB check).
            userType: user.userType,
            onboardingComplete: user.onboardingComplete || false,
        },
        process.env.JWT_SECRET,
        { expiresIn: '30d' } // Token expiry
    );

    // Set token as an HTTP-only cookie
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