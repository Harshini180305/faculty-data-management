const express = require('express');
const router = express.Router();
const otpStore = new Map(); // In-memory storage for OTPs

// Verify OTP route
router.post('/verify-otp', (req, res) => {
  const { email, otp } = req.body;

  // Check if OTP exists for the given email
  if (!otpStore.has(email)) {
    return res.status(400).json({ error: 'OTP not sent for this email.' });
  }

  // Check if entered OTP matches the stored OTP
  if (otpStore.get(email).otp === otp) {
    otpStore.delete(email); // OTP verified, remove from store
    res.status(200).json({ success: true, message: 'OTP verified successfully' });
  } else {
    res.status(400).json({ error: 'Invalid OTP.' });
  }
});

module.exports = router;
