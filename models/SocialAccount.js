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
        enum: ['INSTAGRAM', 'FACEBOOK', 'LINKEDIN'], 
        required: true 
    },
    platformId: { type: String, required: true }, // IG Business ID, FB Page ID, or LinkedIn URN
    accessToken: { type: String, required: true }, // Long-lived token
    tokenExpires: Date,
    followersCount: { type: Number, default: 0 },
    lastSynced: Date,
}, { timestamps: true });

const SocialAccount = mongoose.model('SocialAccount', SocialAccountSchema);
export default SocialAccount;