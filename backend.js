const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const fs = require('fs');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Ensure Uploads directory exists
const uploadsDir = path.join(__dirname, 'Uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
  console.log('Created Uploads directory');
}
app.use('/uploads', express.static(uploadsDir));

// Serve static frontend files
app.use(express.static(path.join(__dirname, '')));

// MongoDB connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://0.0.0.0:27017/facultyDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(async () => {
    console.log('MongoDB connected');

    try {
      await mongoose.connection.db.collection('users').dropIndex('email_1');
      console.log('Dropped existing email_1 index');
    } catch (error) {
      if (error.codeName !== 'IndexNotFound') {
        console.error('Error dropping email_1 index:', error.message);
      }
    }

    await User.createIndexes();
    console.log('User indexes created');

    await initializeHODAccounts();
    await initializeSampleFaculty();
    await initializeAdminAccount();
  })
  .catch(err => console.error('MongoDB connection error:', err.message));

// Schemas
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: function() { return this.role !== 'faculty'; },
    unique: true,
    sparse: true
  },
  email: {
    type: String,
    required: function() { return this.role === 'faculty'; },
    unique: true,
    sparse: true,
    lowercase: true,
    trim: true,
    match: [
      /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      'Please enter a valid email address'
    ]
  },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'hod', 'faculty'], required: true },
  department: { 
    type: String, 
    required: function() { return this.role === 'faculty' || this.role === 'hod'; },
    enum: ['CSE', 'CSM', 'CSD', 'IT'],
    uppercase: true
  },
  name: { type: String, required: true },
  phone: { type: String, match: /^[6-9][0-9]{9}$/ },
  otp: String,
  otpExpires: Date
}, {
  autoIndex: false
});

const facultyProfileSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, match: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/ },
  name: { type: String, required: true },
  dob: Date,
  phone: { type: String, match: /^[6-9][0-9]{9}$/ },
  gender: { type: String, enum: ['Male', 'Female', 'Other'] },
  aadhar: { type: String, match: /^[0-9]{12}$/ },
  aadharPath: String,
  pan: { type: String, match: /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/ },
  panPath: String,
  sscSchool: String,
  sscBoard: String,
  sscPercent: { type: Number, min: 0, max: 100 },
  sscYear: { type: Number, min: 1975, max: 2025 },
  sscCertPath: String,
  interCollege: String,
  interPercent: { type: Number, min: 0, max: 100 },
  interYear: { type: Number, min: 1975, max: 2025 },
  interCertPath: String,
  degCollege: String,
  degBranch: String,
  degCGPA: { type: Number, min: 0, max: 10 },
  degYear: { type: Number, min: 1975, max: 2025 },
  degCertPath: String,
  phdStatus: { type: String, enum: ['Pursuing', 'Completed', ''] },
  phdDetails: String,
  experience: { type: Number, min: 0, max: 50 },
  awards: String,
  awardsCertPaths: [String],
  awardYears: [{ type: Number, min: 1900, max: 2025 }],
  certs: String,
  certsPaths: [String],
  certYears: [{ type: Number, min: 1900, max: 2025 }],
  research: String,
  researchPapers: [String],
  conferences: [{
    type: Object,
    name: String,
    organizedBy: String,
    isbn: String
  }],
  conferenceCerts: [String],
  photoPath: String,
  joinDate: { type: Date, default: Date.now },
  performanceScore: { type: Number, min: 0, max: 100 },
  workloadHours: { type: Number, min: 0 }
});

facultyProfileSchema.index({ email: 1 }, { unique: true });

const User = mongoose.model('User', userSchema);
const FacultyProfile = mongoose.model('FacultyProfile', facultyProfileSchema);

// Multer setup
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|pdf/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) return cb(null, true);
    cb(new Error('Only images and PDFs are allowed'));
  }
});

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'azeemafirdous14@gmail.com',
    pass: process.env.EMAIL_PASS || 'krvf ujuo axfy jwna'
  }
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Middleware to verify JWT
const authenticateAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized: Admin access required' });
    }
    req.user = decoded;
    next();
  } catch (error) {
    console.error('JWT verification error:', error.message);
    res.status(401).json({ error: 'Invalid token', details: error.message });
  }
};

// Generate OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Initialize Admin Account
async function initializeAdminAccount() {
  try {
    const adminExists = await User.findOne({ role: 'admin' });
    if (adminExists) {
      console.log('Admin account already exists, skipping initialization.');
      return;
    }

    const hashedPassword = await bcrypt.hash('admin123', 10);
    const admin = new User({
      username: 'admin',
      password: hashedPassword,
      role: 'admin',
      name: 'Administrator'
    });
    await admin.save();
    console.log('Admin account created with username: admin, password: admin123');
  } catch (error) {
    console.error('Error initializing admin account:', error.message);
  }
}

// Initialize Sample Faculty Data
const sampleFaculty = [
  { email: 'john.doe@cse.example.com', password: 'Password123', name: 'John Doe', phone: '9876543210', department: 'CSE' },
  { email: 'jane.doe@csm.example.com', password: 'Password123', name: 'Jane Doe', phone: '9876543211', department: 'CSM' },
  { email: 'alice.smith@csd.example.com', password: 'Password123', name: 'Alice Smith', phone: '9876543212', department: 'CSD' },
  { email: 'bob.jones@it.example.com', password: 'Password123', name: 'Bob Jones', phone: '9876543213', department: 'IT' }
];

const sampleFacultyProfiles = [
  {
    email: 'john.doe@cse.example.com',
    name: 'John Doe',
    certs: 'Java Certification,Python Certification',
    certYears: [2023, 2024],
    certsPaths: ['uploads/java-cert-john.pdf', 'uploads/python-cert-john.pdf'],
    awards: 'Best Teacher Award,Research Excellence',
    awardYears: [2022, 2023],
    awardsCertPaths: ['uploads/best-teacher-john.pdf', 'Uploads/research-excellence-john.pdf'],
    experience: 5,
    phdStatus: 'Completed',
    researchPapers: ['uploads/research-john1.pdf', 'uploads/research-john2.pdf'],
    photoPath: 'uploads/john-doe.jpg'
  },
  {
    email: 'jane.doe@csm.example.com',
    name: 'Jane Doe',
    certs: 'AWS Certification,Data Science Bootcamp',
    certYears: [2022, 2023],
    certsPaths: ['uploads/aws-cert-jane.pdf', 'uploads/data-science-jane.pdf'],
    awards: 'Innovator Award,Top Performer',
    awardYears: [2021, 2022],
    awardsCertPaths: ['uploads/innovator-jane.pdf', 'Uploads/top-performer-jane.pdf'],
    experience: 3,
    phdStatus: 'Pursuing',
    researchPapers: ['uploads/research-jane1.pdf'],
    photoPath: 'uploads/jane-doe.jpg'
  },
  {
    email: 'alice.smith@csd.example.com',
    name: 'Alice Smith',
    certs: 'Cybersecurity Cert,AI Fundamentals',
    certYears: [2023, 2024],
    certsPaths: ['uploads/cybersecurity-alice.pdf', 'Uploads/ai-fundamentals-alice.pdf'],
    awards: 'Leadership Award,Best Paper',
    awardYears: [2022, 2023],
    awardsCertPaths: ['uploads/leadership-alice.pdf', 'uploads/best-paper-alice.pdf'],
    experience: 4,
    phdStatus: 'Completed',
    researchPapers: ['uploads/research-alice1.pdf', 'Uploads/research-alice2.pdf'],
    photoPath: 'uploads/alice-smith.jpg'
  },
  {
    email: 'bob.jones@it.example.com',
    name: 'Bob Jones',
    certs: 'Network Security,Cloud Computing',
    certYears: [2021, 2022],
    certsPaths: ['uploads/network-security-bob.pdf', 'uploads/cloud-computing-bob.pdf'],
    awards: 'Excellence in IT,Team Lead Award',
    awardYears: [2020, 2021],
    awardsCertPaths: ['uploads/excellence-it-bob.pdf', 'Uploads/team-lead-bob.pdf'],
    experience: 6,
    phdStatus: 'Completed',
    researchPapers: ['uploads/research-bob1.pdf'],
    photoPath: 'uploads/bob-jones.jpg'
  }
];

async function initializeSampleFaculty() {
  try {
    const shouldReset = process.env.RESET_SAMPLE_DATA === 'true';
    const facultyCount = await User.countDocuments({ role: 'faculty' });

    if (!shouldReset && facultyCount > 0) {
      console.log('Faculty data already exists, skipping sample data initialization.');
      return;
    }

    console.log('Initializing sample faculty data...');
    await User.deleteMany({ role: 'faculty' });
    await FacultyProfile.deleteMany({});
    console.log('Cleared existing faculty accounts and profiles');

    for (const faculty of sampleFaculty) {
      const hashedPassword = await bcrypt.hash(faculty.password, 10);
      const newFaculty = new User({
        email: faculty.email.toLowerCase(),
        password: hashedPassword,
        role: 'faculty',
        department: faculty.department.toUpperCase(),
        name: faculty.name,
        phone: faculty.phone
      });
      await newFaculty.save();
      console.log(`Created faculty account for ${faculty.email} in ${faculty.department}`);
    }

    for (const profile of sampleFacultyProfiles) {
      const certTitles = profile.certs ? profile.certs.split(',').map(t => t.trim()).filter(t => t) : [];
      const awardTitles = profile.awards ? profile.awards.split(',').map(t => t.trim()).filter(t => t) : [];

      const certYears = profile.certYears || Array(certTitles.length).fill(new Date().getFullYear());
      const awardYears = profile.awardYears || Array(awardTitles.length).fill(new Date().getFullYear());
      const certsPaths = profile.certsPaths || Array(certTitles.length).fill('uploads/placeholder.pdf');
      const awardsCertPaths = profile.awardsCertPaths || Array(awardTitles.length).fill('uploads/placeholder.pdf');

      const newProfile = new FacultyProfile({
        ...profile,
        email: profile.email.toLowerCase(),
        joinDate: new Date(),
        performanceScore: Math.floor(Math.random() * 100) + 1,
        workloadHours: Math.floor(Math.random() * 40) + 10,
        certYears,
        awardsCertPaths,
        certsPaths,
        awardYears
      });
      await newProfile.save();
      console.log(`Created faculty profile for ${profile.email}`);
    }
    console.log('Sample faculty data initialized successfully.');
  } catch (error) {
    console.error('Error initializing sample faculty:', error.message);
  }
}

// Initialize HOD Accounts
const predefinedHODs = [
  { username: 'hod_cse', password: 'cse123', department: 'CSE', name: 'CSE HOD' },
  { username: 'hod_csm', password: 'csm123', department: 'CSM', name: 'CSM HOD' },
  { username: 'hod_csd', password: 'csd123', department: 'CSD', name: 'CSD HOD' },
  { username: 'hod_it', password: 'it123', department: 'IT', name: 'IT HOD' }
];

async function initializeHODAccounts() {
  try {
    const shouldReset = process.env.RESET_HOD_DATA === 'true';
    const hodCount = await User.countDocuments({ role: 'hod' });

    if (!shouldReset && hodCount > 0) {
      console.log('HOD data already exists, skipping HOD data initialization.');
      return;
    }

    console.log('Initializing HOD accounts...');
    await User.deleteMany({ role: 'hod' });
    console.log('Cleared existing HOD accounts');

    for (const hod of predefinedHODs) {
      const hashedPassword = await bcrypt.hash(hod.password, 10);
      const newHOD = new User({
        username: hod.username.toLowerCase(),
        password: hashedPassword,
        role: 'hod',
        department: hod.department.toUpperCase(),
        name: hod.name
      });
      await newHOD.save();
      console.log(`Created HOD account for ${hod.department}`);
    }
    console.log('HOD accounts initialized successfully.');
  } catch (error) {
    console.error('Error initializing HOD accounts:', error.message);
  }
}

// Admin Login
app.post('/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await User.findOne({
      username: { $regex: `^${username}$`, $options: 'i' },
      role: 'admin'
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or role' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      token,
      username: user.username,
      name: user.name,
      redirect: 'admin_dashboard.html'
    });
  } catch (error) {
    console.error('Admin login error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Fetch All Faculty
app.get('/api/faculty', authenticateAdmin, async (req, res) => {
  try {
    const users = await User.find({ role: 'faculty' });
    const profiles = await FacultyProfile.find({
      email: { $in: users.map(user => user.email.toLowerCase()) }
    });

    const facultyList = users.map(user => {
      const profile = profiles.find(p => p.email.toLowerCase() === user.email.toLowerCase());
      return {
        ...(profile ? profile.toObject() : {}),
        email: user.email,
        name: user.name,
        department: user.department,
        phone: user.phone
      };
    });

    res.json(facultyList);
  } catch (error) {
    console.error('Get all faculty error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Fetch Faculty Documents
app.get('/api/faculty-documents', authenticateAdmin, async (req, res) => {
  try {
    const { department } = req.query;
    let users = [];

    if (department && department.toUpperCase() !== 'ALL') {
      users = await User.find({
        role: 'faculty',
        department: { $regex: `^${department}$`, $options: 'i' }
      });
    } else {
      users = await User.find({ role: 'faculty' });
    }

    const profiles = await FacultyProfile.find({
      email: { $in: users.map(user => user.email.toLowerCase()) }
    });

    const facultyList = users.map(user => {
      const profile = profiles.find(p => p.email.toLowerCase() === user.email.toLowerCase());
      return {
        ...(profile ? profile.toObject() : {}),
        email: user.email,
        name: user.name,
        department: user.department,
        phone: user.phone
      };
    });

    res.json(facultyList);
  } catch (error) {
    console.error('Get faculty documents error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// HOD Login
app.post('/hod/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await User.findOne({
      username: { $regex: `^${username}$`, $options: 'i' },
      role: 'hod'
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or role' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    res.json({
      department: user.department,
      redirect: 'hod_dashboard.html',
      name: user.name,
      username: user.username
    });
  } catch (error) {
    console.error('HOD login error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Get HOD Details
app.get('/api/hod/:username', async (req, res) => {
  try {
    const user = await User.findOne({
      username: { $regex: `^${req.params.username}$`, $options: 'i' },
      role: 'hod'
    });

    if (!user) {
      return res.status(404).json({ error: 'HOD not found' });
    }

    res.json({
      username: user.username,
      name: user.name,
      department: user.department
    });
  } catch (error) {
    console.error('Get HOD details error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Fetch Faculty by Department
app.get('/api/faculty/department/:department', async (req, res) => {
  try {
    const department = req.params.department.toUpperCase();
    const hodUsername = req.query.username;

    console.log(`Fetching faculty for department: ${department}, HOD username: ${hodUsername}`);

    const hod = await User.findOne({
      username: { $regex: `^${hodUsername}$`, $options: 'i' },
      role: 'hod',
      department: department
    });

    if (!hod) {
      console.log('HOD not found or invalid department access');
      return res.status(403).json({ 
        error: 'Unauthorized: You can only access faculty from your own department',
        details: `HOD ${hodUsername} tried to access ${department} data`
      });
    }

    console.log(`Verified HOD: ${hod.username} for department: ${hod.department}`);

    const users = await User.find({
      department: { $regex: `^${department}$`, $options: 'i' },
      role: 'faculty'
    });

    console.log(`Found ${users.length} faculty members in ${department}`);

    if (users.length === 0) {
      return res.status(404).json({ error: 'No faculty found in this department' });
    }

    const profiles = await FacultyProfile.find({
      email: { $in: users.map(user => user.email.toLowerCase()) }
    });

    console.log(`Found ${profiles.length} profiles for faculty in ${department}`);

    const facultyList = users.map(user => {
      const profile = profiles.find(p => p.email.toLowerCase() === user.email.toLowerCase());
      const facultyData = {
        ...(profile ? profile.toObject() : {}),
        email: user.email,
        name: user.name,
        department: user.department,
        phone: user.phone
      };

      if (facultyData.certs && facultyData.certYears) {
        const certTitles = facultyData.certs.split(',').map(t => t.trim()).filter(t => t);
        if (facultyData.certYears.length !== certTitles.length) {
          console.warn(`Adjusting certYears for ${user.email}: ${facultyData.certYears.length} years, ${certTitles.length} certs`);
          facultyData.certYears = Array(certTitles.length).fill(new Date().getFullYear()).map((val, idx) => facultyData.certYears[idx] || val);
        }
      }

      if (facultyData.awards && facultyData.awardYears) {
        const awardTitles = facultyData.awards.split(',').map(t => t.trim()).filter(t => t);
        if (facultyData.awardYears.length !== awardTitles.length) {
          console.warn(`Adjusting awardYears for ${user.email}: ${facultyData.awardYears.length} years, ${awardTitles.length} awards`);
          facultyData.awardYears = Array(awardTitles.length).fill(new Date().getFullYear()).map((val, idx) => facultyData.awardYears[idx] || val);
        }
      }

      return facultyData;
    });

    console.log(`Returning faculty list for ${department}`);
    res.json(facultyList);
  } catch (error) {
    console.error('Get department faculty error:', error.message);
    res.status(500).json({ error: 'Failed to fetch department faculty', details: error.message });
  }
});

// Faculty Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({
      email: { $regex: `^${email}$`, $options: 'i' },
      role: 'faculty'
    });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or role' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    const profile = await FacultyProfile.findOne({ email: { $regex: `^${email}$`, $options: 'i' } });
    res.json({
      exists: !!profile,
      name: user.name,
      department: user.department,
      email: user.email,
      redirect: 'facultydashboard.html'
    });
  } catch (error) {
    console.error('Faculty login error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Forgot Password
app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const user = await User.findOne({
      email: { $regex: `^${email}$`, $options: 'i' },
      role: 'faculty'
    });
    if (!user) {
      return res.status(404).json({ error: 'Email not found' });
    }

    const otp = generateOTP();
    user.otp = otp;
    user.otpExpires = Date.now() + 10 * 60 * 1000;
    await user.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER || 'azeemafirdous14@gmail.com',
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP is ${otp}. It expires in 10 minutes.`
    });

    res.json({ message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Forgot password error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }

    const user = await User.findOne({
      email: { $regex: `^${email}$`, $options: 'i' },
      otp,
      otpExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.json({ message: 'OTP verified' });
  } catch (error) {
    console.error('Verify OTP error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Reset Password
app.post('/reset-password', async (req, res) => {
  try {
    const { email, newPassword, confirmPassword } = req.body;
    if (!email || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'Email and passwords are required' });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }

    const user = await User.findOne({
      email: { $regex: `^${email}$`, $options: 'i' }
    });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Register Faculty
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name, phone, department } = req.body;
    const nameRegex = /^[A-Za-z\s]{2,30}$/;
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{6,20}$/;
    const phoneRegex = /^[6-9][0-9]{9}$/;

    if (!nameRegex.test(name)) {
      return res.status(400).json({ error: 'Name must be 2-30 characters, letters and spaces only' });
    }
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    if (!passwordRegex.test(password)) {
      return res.status(400).json({ error: 'Password must be 6-20 characters, with at least one uppercase, one lowercase, and one number' });
    }
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ error: 'Phone must be a 10-digit Indian mobile number starting with 6-9' });
    }
    if (!['CSE', 'CSM', 'CSD', 'IT'].includes(department.toUpperCase())) {
      return res.status(400).json({ error: 'Invalid department' });
    }

    const existingUser = await User.findOne({ email: { $regex: `^${email}$`, $options: 'i' } });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      email: email.toLowerCase(),
      password: hashedPassword,
      role: 'faculty',
      name,
      phone,
      department: department.toUpperCase()
    });
    await user.save();

    res.json({ message: 'Registration successful', redirect: 'sampleloginfaculty.html' });
  } catch (error) {
    console.error('Registration error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Get Faculty Profile
app.get('/api/faculty/:email', async (req, res) => {
  try {
    console.log('Received GET /api/faculty/:email request for:', req.params.email);
    
    const profile = await FacultyProfile.findOne({
      email: { $regex: `^${req.params.email}$`, $options: 'i' }
    });

    const user = await User.findOne({ 
      email: { $regex: `^${req.params.email}$`, $options: 'i' },
      role: 'faculty'
    });

    if (!user) {
      console.log('Faculty user not found for:', req.params.email);
      return res.status(404).json({ error: 'Faculty user not found' });
    }

    if (!profile) {
      console.log('No profile exists for:', req.params.email);
      return res.json({ 
        exists: false, 
        profile: { 
          email: user.email,
          name: user.name,
          department: user.department,
          phone: user.phone
        }
      });
    }

    console.log('Returning profile data for:', req.params.email);
    res.json({
      exists: true,
      profile: {
        ...profile.toObject(),
        department: user.department,
        phone: user.phone,
        dob: profile.dob || undefined,
        gender: profile.gender || undefined,
        aadhar: profile.aadhar || undefined,
        aadharPath: profile.aadharPath || undefined,
        pan: profile.pan || undefined,
        panPath: profile.panPath || undefined,
        sscSchool: profile.sscSchool || undefined,
        sscBoard: profile.sscBoard || undefined,
        sscPercent: profile.sscPercent || undefined,
        sscYear: profile.sscYear || undefined,
        sscCertPath: profile.sscCertPath || undefined,
        interCollege: profile.interCollege || undefined,
        interPercent: profile.interPercent || undefined,
        interYear: profile.interYear || undefined,
        interCertPath: profile.interCertPath || undefined,
        degCollege: profile.degCollege || undefined,
        degBranch: profile.degBranch || undefined,
        degCGPA: profile.degCGPA || undefined,
        degYear: profile.degYear || undefined,
        degCertPath: profile.degCertPath || undefined,
        phdStatus: profile.phdStatus || undefined,
        phdDetails: profile.phdDetails || undefined,
        experience: profile.experience || 0,
        awards: profile.awards || undefined,
        awardsCertPaths: profile.awardsCertPaths || [],
        awardYears: profile.awardYears || [],
        certs: profile.certs || undefined,
        certsPaths: profile.certsPaths || [],
        certYears: profile.certYears || [],
        research: profile.research || undefined,
        researchPapers: profile.researchPapers || [],
        conferences: profile.conferences || [],
        conferenceCerts: profile.conferenceCerts || [],
        photoPath: profile.photoPath || undefined,
        joinDate: profile.joinDate || undefined,
        performanceScore: profile.performanceScore || undefined,
        workloadHours: profile.workloadHours || undefined
      }
    });
  } catch (error) {
    console.error('Get profile error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Create/Update Faculty Profile
app.post('/api/faculty', upload.fields([
  { name: 'photo', maxCount: 1 },
  { name: 'aadharUpload', maxCount: 1 },
  { name: 'panUpload', maxCount: 1 },
  { name: 'sscCertificate', maxCount: 1 },
  { name: 'interCertificate', maxCount: 1 },
  { name: 'degCertificate', maxCount: 1 },
  { name: 'awardsUpload', maxCount: 10 },
  { name: 'certsUpload', maxCount: 10 },
  { name: 'researchPapers', maxCount: 10 },
  { name: 'conferenceCertificates', maxCount: 10 }
]), async (req, res) => {
  try {
    console.log('Received POST /api/faculty request');
    console.log('Body:', req.body);
    console.log('Files:', Object.keys(req.files || {}).map(key => ({ field: key, files: req.files[key].map(f => f.originalname) })));

    const {
      email, name, dob, phone, gender, aadhar, pan,
      sscSchool, sscBoard, sscPercent, sscYear,
      interCollege, interPercent, interYear,
      degCollege, degBranch, degCGPA, degYear,
      phdStatus, phdDetails, experience, awards, awardYears,
      certs, certYears, research, conferences,
      performanceScore, workloadHours
    } = req.body;

    // Required fields validation
    if (!email || !name) {
      return res.status(400).json({ error: 'Email and name are required' });
    }

    // Additional validations (allow partial data)
    if (phone && !/^[6-9][0-9]{9}$/.test(phone)) {
      console.warn(`Invalid phone number for ${email}: ${phone}`);
      req.body.phone = undefined;
    }
    if (aadhar && !/^[0-9]{12}$/.test(aadhar)) {
      console.warn(`Invalid Aadhar number for ${email}: ${aadhar}`);
      req.body.aadhar = undefined;
    }
    if (pan && !/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/.test(pan)) {
      console.warn(`Invalid PAN number for ${email}: ${pan}`);
      req.body.pan = undefined;
    }
    if (sscPercent && (isNaN(sscPercent) || sscPercent < 0 || sscPercent > 100)) {
      console.warn(`Invalid SSC percentage for ${email}: ${sscPercent}`);
      req.body.sscPercent = undefined;
    }
    if (interPercent && (isNaN(interPercent) || interPercent < 0 || interPercent > 100)) {
      console.warn(`Invalid Intermediate percentage for ${email}: ${interPercent}`);
      req.body.interPercent = undefined;
    }
    if (degCGPA && (isNaN(degCGPA) || degCGPA < 0 || degCGPA > 10)) {
      console.warn(`Invalid Degree CGPA for ${email}: ${degCGPA}`);
      req.body.degCGPA = undefined;
    }
    if (sscYear && (isNaN(sscYear) || sscYear < 1975 || sscYear > 2025)) {
      console.warn(`Invalid SSC year for ${email}: ${sscYear}`);
      req.body.sscYear = undefined;
    }
    if (interYear && (isNaN(interYear) || interYear < 1975 || interYear > 2025)) {
      console.warn(`Invalid Intermediate year for ${email}: ${interYear}`);
      req.body.interYear = undefined;
    }
    if (degYear && (isNaN(degYear) || degYear < 1975 || degYear > 2025)) {
      console.warn(`Invalid Degree year for ${email}: ${degYear}`);
      req.body.degYear = undefined;
    }
    if (experience && (isNaN(experience) || experience < 0 || experience > 50)) {
      console.warn(`Invalid experience for ${email}: ${experience}`);
      req.body.experience = undefined;
    }
    if (performanceScore && (isNaN(performanceScore) || performanceScore < 0 || performanceScore > 100)) {
      console.warn(`Invalid performance score for ${email}: ${performanceScore}`);
      req.body.performanceScore = undefined;
    }
    if (workloadHours && (isNaN(workloadHours) || workloadHours < 0)) {
      console.warn(`Invalid workload hours for ${email}: ${workloadHours}`);
      req.body.workloadHours = undefined;
    }

    // File paths (handle missing files gracefully)
    const photoPath = req.files['photo']?.[0]?.path?.replace(/\\/g, '/');
    const aadharPath = req.files['aadharUpload']?.[0]?.path?.replace(/\\/g, '/');
    const panPath = req.files['panUpload']?.[0]?.path?.replace(/\\/g, '/');
    const sscCertPath = req.files['sscCertificate']?.[0]?.path?.replace(/\\/g, '/');
    const interCertPath = req.files['interCertificate']?.[0]?.path?.replace(/\\/g, '/');
    const degCertPath = req.files['degCertificate']?.[0]?.path?.replace(/\\/g, '/');
    const awardsCertPaths = req.files['awardsUpload'] ? req.files['awardsUpload'].map(file => file.path.replace(/\\/g, '/')) : [];
    const certsPaths = req.files['certsUpload'] ? req.files['certsUpload'].map(file => file.path.replace(/\\/g, '/')) : [];
    const researchPapers = req.files['researchPapers'] ? req.files['researchPapers'].map(file => file.path.replace(/\\/g, '/')) : [];
    const conferenceCerts = req.files['conferenceCertificates'] ? req.files['conferenceCertificates'].map(file => file.path.replace(/\\/g, '/')) : [];

    // Parse arrays
    let parsedConferences = [];
    if (conferences) {
      if (typeof conferences === 'string') {
        try {
          parsedConferences = JSON.parse(conferences);
          if (!Array.isArray(parsedConferences)) {
            console.warn(`Conferences is not an array for ${email}: ${conferences}`);
            parsedConferences = [];
          }
        } catch (e) {
          console.warn(`Invalid conferences JSON for ${email}: ${e.message}`);
          parsedConferences = [];
        }
      } else if (Array.isArray(conferences)) {
        parsedConferences = conferences;
      } else {
        console.warn(`Invalid conferences format for ${email}, expected JSON string or array`);
        parsedConferences = [];
      }
      parsedConferences = parsedConferences.filter(conf => {
        const isValid = conf && typeof conf === 'object' && conf.name && conf.organizedBy && conf.isbn;
        if (!isValid) console.warn(`Skipping invalid conference for ${email}: ${JSON.stringify(conf)}`);
        return isValid;
      });
    }

    let parsedAwardYears = [];
    if (awardYears) {
      if (typeof awardYears === 'string') {
        parsedAwardYears = awardYears.split(',')
          .map(year => parseInt(year.trim()))
          .filter(year => !isNaN(year) && year >= 1900 && year <= 2025);
      } else if (Array.isArray(awardYears)) {
        parsedAwardYears = awardYears
          .map(year => parseInt(year))
          .filter(year => !isNaN(year) && year >= 1900 && year <= 2025);
      }
      if (!parsedAwardYears.length && awardYears) {
        console.warn(`No valid award years for ${email}: ${awardYears}`);
      }
    }

    let parsedCertYears = [];
    if (certYears) {
      if (typeof certYears === 'string') {
        parsedCertYears = certYears.split(',')
          .map(year => parseInt(year.trim()))
          .filter(year => !isNaN(year) && year >= 1900 && year <= 2025);
      } else if (Array.isArray(certYears)) {
        parsedCertYears = certYears
          .map(year => parseInt(year))
          .filter(year => !isNaN(year) && year >= 1900 && year <= 2025);
      }
      if (!parsedCertYears.length && certYears) {
        console.warn(`No valid cert years for ${email}: ${certYears}`);
      }
    }

    const certTitles = certs ? certs.split(',').map(t => t.trim()).filter(t => t) : [];
    const awardTitles = awards ? awards.split(',').map(t => t.trim()).filter(t => t) : [];

    // Adjust arrays to match titles
    if (parsedCertYears.length && parsedCertYears.length !== certTitles.length) {
      console.warn(`Cert years mismatch for ${email}: ${parsedCertYears.length} years, ${certTitles.length} certs`);
      parsedCertYears = parsedCertYears.slice(0, certTitles.length);
      while (parsedCertYears.length < certTitles.length) parsedCertYears.push(new Date().getFullYear());
    }
    if (certsPaths.length && certsPaths.length !== certTitles.length) {
      console.warn(`Certs paths mismatch for ${email}: ${certsPaths.length} paths, ${certTitles.length} certs`);
      certsPaths.length = certTitles.length;
    }
    if (parsedAwardYears.length && parsedAwardYears.length !== awardTitles.length) {
      console.warn(`Award years mismatch for ${email}: ${parsedAwardYears.length} years, ${awardTitles.length} awards`);
      parsedAwardYears = parsedAwardYears.slice(0, awardTitles.length);
      while (parsedAwardYears.length < awardTitles.length) parsedAwardYears.push(new Date().getFullYear());
    }
    if (awardsCertPaths.length && awardsCertPaths.length !== awardTitles.length) {
      console.warn(`Awards paths mismatch for ${email}: ${awardsCertPaths.length} paths, ${awardTitles.length} awards`);
      awardsCertPaths.length = awardTitles.length;
    }

    const user = await User.findOne({ 
      email: { $regex: `^${email}$`, $options: 'i' }, 
      role: 'faculty' 
    });
    if (!user) {
      return res.status(404).json({ error: 'Faculty user not found', details: `No faculty user with email ${email} exists` });
    }

    const profileData = {
      email: email.toLowerCase(),
      name,
      dob: dob ? new Date(dob) : undefined,
      phone,
      gender,
      aadhar,
      aadharPath,
      pan,
      panPath,
      sscSchool,
      sscBoard,
      sscPercent: sscPercent ? parseFloat(sscPercent) : undefined,
      sscYear: sscYear ? parseInt(sscYear) : undefined,
      sscCertPath,
      interCollege,
      interPercent: interPercent ? parseFloat(interPercent) : undefined,
      interYear: interYear ? parseInt(interYear) : undefined,
      interCertPath,
      degCollege,
      degBranch,
      degCGPA: degCGPA ? parseFloat(degCGPA) : undefined,
      degYear: degYear ? parseInt(degYear) : undefined,
      degCertPath,
      phdStatus,
      phdDetails,
      experience: experience ? parseInt(experience) : 0,
      awards,
      awardsCertPaths,
      awardYears: parsedAwardYears,
      certs,
      certsPaths,
      certYears: parsedCertYears,
      research,
      researchPapers,
      conferences: parsedConferences,
      conferenceCerts,
      photoPath,
      joinDate: new Date(),
      performanceScore: performanceScore ? parseInt(performanceScore) : undefined,
      workloadHours: workloadHours ? parseInt(workloadHours) : undefined
    };

    console.log('Profile data to save:', JSON.stringify(profileData, null, 2));

    const existingProfile = await FacultyProfile.findOne({ email: { $regex: `^${email}$`, $options: 'i' } });
    if (existingProfile) {
      console.log('Updating existing profile for:', email);
      await FacultyProfile.updateOne(
        { email: { $regex: `^${email}$`, $options: 'i' } },
        { $set: profileData },
        { runValidators: true }
      );
      const updatedProfile = await FacultyProfile.findOne({ email: { $regex: `^${email}$`, $options: 'i' } });
      console.log('Profile updated successfully for:', email);
      return res.json({ 
        message: 'Profile updated successfully',
        exists: true,
        profile: {
          ...updatedProfile.toObject(),
          department: user.department,
          phone: user.phone
        }
      });
    }

    console.log('Creating new profile for:', email);
    const profile = new FacultyProfile(profileData);
    await profile.save();
    console.log('Profile saved successfully for:', email);
    res.json({ 
      message: 'Profile created successfully',
      exists: true,
      profile: {
        ...profile.toObject(),
        department: user.department,
        phone: user.phone
      }
    });
  } catch (error) {
    console.error('Create faculty profile error:', error.message, error.stack);
    res.status(500).json({ 
      error: 'Failed to save profile', 
      details: error.message,
      suggestion: 'Check server logs for details and ensure all fields are correctly formatted'
    });
  }
});

// Debug Endpoint
app.get('/api/debug/profile/:email', async (req, res) => {
  try {
    const email = req.params.email;
    console.log('Debug request for email:', email);

    const user = await User.findOne({ email: { $regex: `^${email}$`, $options: 'i' }, role: 'faculty' });
    const profile = await FacultyProfile.findOne({ email: { $regex: `^${email}$`, $options: 'i' } });

    res.json({
      userExists: !!user,
      profileExists: !!profile,
      user: user || null,
      profile: profile || null
    });
  } catch (error) {
    console.error('Debug endpoint error:', error.message);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});