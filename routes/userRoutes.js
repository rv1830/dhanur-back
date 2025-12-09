// routes/userRoutes.js
import express from 'express';
import { authUser, registerUser } from '../controllers/userController.js';

const router = express.Router();

// Public routes for user auth
router.post('/login', authUser);
router.post('/', registerUser); 

export default router;