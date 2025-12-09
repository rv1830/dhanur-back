// models/SocialAccount.js
import mongoose from 'mongoose';

const SocialAccountSchema = mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    platform: { 
        type: String, 
        // ✅ UPDATED ENUM
        enum: ['INSTAGRAM', 'FACEBOOK', 'LINKEDIN', 'SNAPCHAT', 'YOUTUBE', 'TWITTER'], 
        required: true 
    },
    platformId: { type: String, required: true }, // Unique ID: IG Business ID, FB Page ID, LI URN, Snap User ID, YouTube Channel ID, Twitter User ID
    accessToken: { type: String, required: true }, // Long-lived token
    tokenExpires: Date,
    followersCount: { type: Number, default: 0 },
    lastSynced: Date,
}, { timestamps: true });

const SocialAccount = mongoose.model('SocialAccount', SocialAccountSchema);
export default SocialAccount;