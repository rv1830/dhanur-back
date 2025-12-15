// --- models/InstagramAnalytics.js (NEW) ---
import mongoose from 'mongoose';

const InstagramAnalyticsSchema = mongoose.Schema({
    socialAccountId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'SocialAccount',
        required: true,
    },
    date: { type: Date, required: true, index: true }, 

    // --- Core Instagram Metrics ---
    reach: { type: Number, default: 0 },
    impressions: { type: Number, default: 0 },
    profileViews: { type: Number, default: 0 }, 
    
    // --- Engagement Metrics ---
    engagement: { type: Number, default: 0 },
    postReactions: { type: Number, default: 0 },
    // You can add fields for specific post data here if needed later

    // Ensures only one record per account per day
    unique: ['socialAccountId', 'date']
}, { timestamps: true });

const InstagramAnalytics = mongoose.model('InstagramAnalytics', InstagramAnalyticsSchema);
export default InstagramAnalytics;