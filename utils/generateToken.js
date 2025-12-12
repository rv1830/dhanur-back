// utils/generateToken.js
import jwt from 'jsonwebtoken';

const generateToken = (user) => {
    return jwt.sign(
        {
            id: user._id,
            email: user.email,
            phoneNumber: user.phoneNumber,
            userType: user.userType,
            tokenVersion: user.tokenVersion || 0,
        },
        process.env.JWT_SECRET,
        { expiresIn: '30d' }
    );
};

export default generateToken;