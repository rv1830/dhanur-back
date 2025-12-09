// utils/generateToken.js
import jwt from 'jsonwebtoken';

/**
 * Generates a JWT token for a given user ID.
 * @param {string} id - The MongoDB user ID.
 * @returns {string} The signed JWT token.
 */
const generateToken = (id) => {
    // Uses process.env.JWT_SECRET (linkup-secret from your env)
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '30d', // Token valid for 30 days
    });
};

export default generateToken;