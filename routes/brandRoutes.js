import express from 'express';
const router = express.Router();
import { protect } from '../middleware/authMiddleware.js';
import { 
    createBrand, 
    inviteToBrand, 
    getInviteDetails, 
    joinBrand 
} from '../controllers/brandController.js';
import { checkBrandRole } from '../middleware/brandMiddleware.js';

// Public/Semi-public
router.get('/invite-details/:token', getInviteDetails); // Naye user ko brand name dikhane ke liye

// Protected
router.post('/create',protect, createBrand);
router.post('/join', protect, joinBrand);

// Admin/Manager only
router.post('/invite', protect, checkBrandRole(['BRAND ADMIN', 'MANAGER']), inviteToBrand);

export default router;