// utils.js
function generateOTP() {
  const otp = Math.floor(100000 + Math.random() * 900000); // Generates a 6-digit OTP
  return otp.toString();
}

const OTP_EXPIRY_TIME = 5 * 60 * 1000; // OTP expiry time in milliseconds (5 minutes)

module.exports = { generateOTP, OTP_EXPIRY_TIME };
