// --- models/User.js (COMPLETE UPDATED SCHEMA) ---

import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const UserSchema = new mongoose.Schema({
    // =================================================================
    // 🔐 AUTHENTICATION FIELDS
    // =================================================================
    email: { 
        type: String, 
        unique: true, 
        sparse: true,
        lowercase: true,
        trim: true 
    },
    phoneNumber: { 
        type: String, 
        trim: true 
    },
    password: { 
        type: String 
    },
    
    // =================================================================
    // 👤 PROFILE FIELDS
    // =================================================================
    name: { 
        type: String, 
        trim: true 
    },
    dateOfBirth: { 
        type: Date 
    },
    gender: { 
        type: String, 
        enum: ['MALE', 'FEMALE', 'OTHER', null],
        default: null
    },
    profilePicture: { 
        type: String 
    },
    
    // =================================================================
    // 🎭 USER TYPE & ONBOARDING STATUS
    // =================================================================
    userType: { 
        type: String, 
        enum: ['BRAND', 'INFLUENCER', 'ADMIN', null], 
        default: null 
    },
    profileComplete: { 
        type: Boolean, 
        default: false
    },
    onboardingComplete: { 
        type: Boolean, 
        default: false
    },
    
    // =================================================================
    // 🔑 OAUTH & AUTH PROVIDER (UPDATED ENUM)
    // =================================================================
    authProvider: { 
        type: String, 
        enum: ['LOCAL', 'GOOGLE', 'LINKEDIN', 'PHONE', 'FACEBOOK', 'INSTAGRAM'], 
        default: 'LOCAL' 
    },
    googleId: { 
        type: String, 
        unique: true, 
        sparse: true 
    },
    linkedinId: { 
        type: String, 
        unique: true, 
        sparse: true 
    },
    // NEW: Facebook/Meta User ID for dedicated Auth check (optional but good)
    facebookId: { 
        type: String, 
        unique: true, 
        sparse: true 
    }, 
    
    // =================================================================
    // 🔒 SECURITY & VERIFICATION
    // =================================================================
    tokenVersion: { 
        type: Number, 
        default: 0 
    },
    verificationCode: { 
        type: String 
    },
    codeExpiry: { 
        type: Date 
    },
    
    // =================================================================
    // 📝 ADDITIONAL PROFILE INFO
    // =================================================================
    profile: {
        bio: { type: String },
        companyName: { type: String },
        rateCard: { type: mongoose.Schema.Types.Mixed },
    }
    
}, { 
    timestamps: true 
});

// =================================================================
// 🔑 PASSWORD COMPARISON METHOD
// =================================================================
UserSchema.methods.matchPassword = async function(password) {
    return await bcrypt.compare(password, this.password);
};

export default mongoose.model('User', UserSchema);