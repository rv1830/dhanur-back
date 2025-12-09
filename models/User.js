// models/User.js
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const UserSchema = mongoose.Schema({
    email: { 
        type: String, 
        required: true, 
        unique: true 
    },
    password: { 
        type: String, 
        required: true 
    },
    userType: { 
        type: String, 
        enum: ['BRAND', 'INFLUENCER', 'ADMIN'], 
        required: true 
    },
    // Optional: Influencer/Brand specific profile data
    profile: {
        bio: String,
        companyName: String,
        rateCard: mongoose.Schema.Types.Mixed, // Flexible for different rates
    }
}, { 
    timestamps: true 
});

// Middleware: Hash password before saving the user (pre-save hook)
UserSchema.pre('save', async function() {
    
    // Check if the password field was modified (only hash if it's new or updated)
    if (!this.isModified('password')) {
        return; 
    }
    
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method: Compare entered password with the hashed password in the database
UserSchema.methods.matchPassword = async function(enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', UserSchema);

export default User;