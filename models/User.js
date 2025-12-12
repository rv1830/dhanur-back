import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const UserSchema = new mongoose.Schema({
    email: { type: String, unique: true, sparse: true },
    phoneNumber: { type: String, unique: true, sparse: true },
    password: { type: String }, 
    userType: { type: String, enum: ['BRAND', 'INFLUENCER', 'ADMIN'], required: true },
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
