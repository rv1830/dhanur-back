// --- models/SocialAccount.js (UPDATED) ---
import mongoose from 'mongoose';

const SocialAccountSchema = mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    platform: { 
        type: String, 
        // UPDATED ENUM: INSTAGRAM और FACEBOOK को अलग रखा
        enum: ['INSTAGRAM', 'FACEBOOK', 'LINKEDIN', 'SNAPCHAT', 'YOUTUBE', 'TWITTER'], 
        required: true 
    },
    
    // --- Auth & Token Management ---
    platformId: { type: String, required: true, index: true }, 
    accessToken: { type: String, required: true }, 
    refreshToken: { 
        type: String, 
        select: false, // Hides the token by default for security
        required: false 
    }, 
    tokenExpires: Date,
    
    // --- Profile Data (from API) ---
    profileName: { type: String, required: false }, // Channel Title / Username
    followersCount: { type: Number, default: 0 }, // Subscriber / Follower Count
    profilePictureUrl: { type: String, required: false }, 
    channelDescription: { type: String, required: false },
    
    // --- YouTube Statistics (Generic fields kept) ---
    totalVideos: { type: Number, default: 0 }, 
    totalViews: { type: Number, default: 0 }, 
    
    // --- Sync Metadata ---
    lastSynced: Date,

}, { timestamps: true });

SocialAccountSchema.index({ userId: 1, platform: 1 }, { unique: true });

const SocialAccount = mongoose.model('SocialAccount', SocialAccountSchema);
export default SocialAccount;