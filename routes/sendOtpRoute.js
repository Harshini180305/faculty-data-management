const express = require('express');
const router = express.Router();
const nodemailer = require('nodemailer');
const otpStore = new Map();
const { generateOTP } = require('../utils/utils');
require('dotenv').config(); // Ensure this is added

const OTP_EXPIRY_TIME = 5 * 60 * 1000;

router.post('/send-otp', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const otp = generateOTP();
  otpStore.set(email, { otp, time: Date.now() });

  setTimeout(() => otpStore.delete(email), OTP_EXPIRY_TIME);

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  // Debug: Check email config
  transporter.verify((err, success) => {
    if (err) console.error('Email setup error:', err);
    else console.log('Email server ready');
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP Code',
    text: `Your OTP code is: ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ success: true, message: 'OTP sent successfully' });
  } catch (err) {
    console.error('Error sending OTP:', err);
    res.status(500).json({ error: 'Failed to send OTP. Check console for details.' });
  }
});

module.exports = router;
