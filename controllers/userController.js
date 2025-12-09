// controllers/userController.js
import asyncHandler from 'express-async-handler';
import User from '../models/User.js';
import generateToken from '../utils/generateToken.js';

// @desc    Register a new user
// @route   POST /api/users
// @access  Public
export const registerUser = asyncHandler(async (req, res) => {
    const { email, password, userType } = req.body;

    // Validation (assuming basic fields are required)
    if (!email || !password || !userType) {
        res.status(400);
        throw new Error('Please provide email, password, and userType.');
    }
    
    // Check if user already exists
    const userExists = await User.findOne({ email });

    if (userExists) {
        res.status(400); 
        throw new Error('User already exists');
    }

    // Create user (password hashing is handled by the pre-save middleware in User model)
    const user = await User.create({
        email,
        password,
        userType,
    });

    if (user) {
        res.status(201).json({
            _id: user._id,
            email: user.email,
            userType: user.userType,
            token: generateToken(user._id), // Generate REAL JWT
        });
    } else {
        res.status(400);
        throw new Error('Invalid user data');
    }
});

// @desc    Authenticate user & get token
// @route   POST /api/users/login
// @access  Public
export const authUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    // Check if user exists and password matches (using matchPassword method from User model)
    if (user && (await user.matchPassword(password))) {
        res.json({
            _id: user._id,
            email: user.email,
            userType: user.userType,
            token: generateToken(user._id), // Generate REAL JWT
        });
    } else {
        res.status(401); // Unauthorized
        throw new Error('Invalid email or password');
    }
});