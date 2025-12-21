import express from 'express';
const router = express.Router();
import { protect, isBrand } from '../middleware/authMiddleware.js';
import { 
    createBrand, 
    inviteToBrand, 
    getInviteDetails, 
    joinBrand,
    getMyBrands,
    getBrandDetails,
    searchBrands
} from '../controllers/brandController.js';
import { checkBrandRole } from '../middleware/brandMiddleware.js';

// --- Public / General ---
router.get('/invite-details/:token', getInviteDetails);
router.get('/search',protect, searchBrands);
// --- Protected (Login Required) ---
router.post('/create', protect, createBrand);
router.post('/join', protect, joinBrand);
router.get('/my-brands', protect, getMyBrands); // User ke saare brands fetch karne ke liye

// --- Specific Brand Details (bid is used here) ---
router.get('/:bid', protect, getBrandDetails);

// --- Admin/Manager Only ---
router.post('/invite', protect, isBrand, checkBrandRole(['BRAND ADMIN', 'MANAGER']), inviteToBrand);

export default router;