const express = require('express');
const userController = require('../controllers/userController');

const router = express.Router();

// User authentication routes
router.post('/register', userController.register.bind(userController));
router.post('/login', userController.login.bind(userController));

// User profile routes
router.put('/profile', userController.updateProfile.bind(userController));

// Order management routes
router.post('/orders', userController.createOrder.bind(userController));

// Analytics routes
router.get('/analytics', userController.getUserAnalytics.bind(userController));

module.exports = router;