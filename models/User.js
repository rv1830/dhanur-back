import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true, sparse: true },
    phoneNumber: { type: String, unique: true, sparse: true },
    password: { type: String }, 
    
    // =================================================================
    // 🔥 FIXED: userType is now OPTIONAL (required: false) and allows null
    // =================================================================
    userType: { 
        type: String, 
        // 🚨 FIX 1: 'required: true' को हटा दिया गया है
        // Mongoose automatically sets required: false if not specified.
        
        // ✅ FIX 2: 'null' को enum में शामिल किया गया है
        enum: ['BRAND', 'INFLUENCER', 'ADMIN', null], 
        
        // ✅ FIX 3: एक डिफ़ॉल्ट मान (null) सेट किया गया है
        default: null 
    },
    // =================================================================
    
    authProvider: { type: String, enum: ['LOCAL', 'GOOGLE', 'LINKEDIN', 'PHONE'], default: 'LOCAL' },
    googleId: { type: String, unique: true, sparse: true },
    linkedinId: { type: String, unique: true, sparse: true },
    tokenVersion: { type: Number, default: 0 }, 
    verificationCode: { type: String },
    codeExpiry: { type: Date },
    profile: {
        bio: String,
        companyName: String,
        rateCard: mongoose.Schema.Types.Mixed,
    }
}, { timestamps: true });

// ✅ ONLY MATCH PASSWORD - NO PRE-SAVE HOOK
UserSchema.methods.matchPassword = async function(password) {
    return await bcrypt.compare(password, this.password);
};

export default mongoose.model('User', UserSchema);