
const express = require('express');
const router = express.Router();
const { handleContactForm } = require('../controllers/contactControllers');

router.post('/', handleContactForm);

module.exports = router;
