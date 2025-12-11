// models/YouTubeAnalytics.js
import mongoose from 'mongoose';

const YouTubeAnalyticsSchema = mongoose.Schema({
    socialAccountId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'SocialAccount',
        required: true,
    },
    date: { type: Date, required: true, index: true },
    
    // --- Non-Monetary KPIs (from yt-analytics.readonly) ---
    views: { type: Number, default: 0 },
    comments: { type: Number, default: 0 },
    likes: { type: Number, default: 0 },
    shares: { type: Number, default: 0 },
    subscribersGained: { type: Number, default: 0 },
    watchTimeMinutes: { type: Number, default: 0 },
    
    // --- Monetary KPIs (from yt-analytics-monetary.readonly) ---
    estimatedRevenue: { type: Number, default: 0 },
    adImpressions: { type: Number, default: 0 },

    // Ensures only one record per account per day
    unique: ['socialAccountId', 'date']
}, { timestamps: true });

const YouTubeAnalytics = mongoose.model('YouTubeAnalytics', YouTubeAnalyticsSchema);
export default YouTubeAnalytics;