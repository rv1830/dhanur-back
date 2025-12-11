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
    
    // --- Profile Data (from youtube.readonly) ---
    profileName: { type: String, required: false }, // Channel Title
    followersCount: { type: Number, default: 0 }, // Subscriber Count
    profilePictureUrl: { type: String, required: false }, 
    channelDescription: { type: String, required: false },
    
    // --- YouTube Statistics ---
    totalVideos: { type: Number, default: 0 }, 
    totalViews: { type: Number, default: 0 }, 
    
    // --- Sync Metadata ---
    lastSynced: Date,

}, { timestamps: true });

const SocialAccount = mongoose.model('SocialAccount', SocialAccountSchema);
export default SocialAccount;