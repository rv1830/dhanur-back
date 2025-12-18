import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { generateUniquePublicId } from '../utils/idGenerator.js';

const UserSchema = new mongoose.Schema({
    // =================================================================
    // 🔐 AUTHENTICATION FIELDS
    // =================================================================
    uid: { type: String, unique: true, index: true }, // US-1234567890
    email: { 
        type: String, 
        unique: true, 
        sparse: true, 
        lowercase: true, 
        trim: true 
    },
    phoneNumber: { type: String, trim: true },
    password: { type: String },
    
    // =================================================================
    // 👤 PROFILE FIELDS
    // =================================================================
    name: { type: String, trim: true },
    dateOfBirth: { type: Date },
    gender: { 
        type: String, 
        enum: ['MALE', 'FEMALE', 'OTHER', null], // Gender null ho sakta hai jab tak user update na kare
        default: null 
    },
    profilePicture: { type: String },
    
    // =================================================================
    // 🎭 USER TYPE (Strictly No Null)
    // =================================================================
    userType: { 
        type: String, 
        enum: ['BRAND', 'INFLUENCER', 'MEMBER', 'ADMIN'], 
        default: 'MEMBER' // ✅ Naya user default 'MEMBER' banega
    },
    
    profileComplete: { type: Boolean, default: false },
    onboardingComplete: { type: Boolean, default: false },
    
    // =================================================================
    // 🔑 OAUTH PROVIDERS
    // =================================================================
    authProvider: { 
        type: String, 
        enum: ['LOCAL', 'GOOGLE', 'LINKEDIN', 'PHONE', 'FACEBOOK', 'INSTAGRAM'], 
        default: 'LOCAL' 
    },
    googleId: { type: String, unique: true, sparse: true },
    linkedinId: { type: String, unique: true, sparse: true },
    facebookId: { type: String, unique: true, sparse: true }, 
    
    // =================================================================
    // 🔒 SECURITY & VERIFICATION
    // =================================================================
    tokenVersion: { type: Number, default: 0 },
    verificationCode: { type: String },
    codeExpiry: { type: Date },
    
    // =================================================================
    // 📝 ADDITIONAL PROFILE INFO
    // =================================================================
    profile: {
        bio: { type: String },
        companyName: { type: String },
        rateCard: { type: mongoose.Schema.Types.Mixed },
    }
}, { timestamps: true });

// PASSWORD MATCH METHOD
UserSchema.methods.matchPassword = async function(password) {
    return await bcrypt.compare(password, this.password);
};

// PRE-SAVE HOOK FOR UID (Fixed: next parameter is not needed for async)
UserSchema.pre('save', async function () {
    if (!this.uid) {
        this.uid = await generateUniquePublicId(this.constructor, 'USER');
    }
});

export default mongoose.model('User', UserSchema);