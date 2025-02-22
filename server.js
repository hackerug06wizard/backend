import express from 'express';
import cors from 'cors';
import { Twilio } from 'twilio';
import { Octokit } from '@octokit/rest';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Twilio client
const twilioClient = new Twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

// Initialize GitHub client
const octokit = new Octokit({
  auth: process.env.GITHUB_ACCESS_TOKEN
});

// Mock database (replace with actual database in production)
const users = [];

// Helper function to generate JWT
const generateToken = (user) => {
  return jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
};

// Sign up route
app.post('/signup', async (req, res) => {
  const { name, email, password, phone } = req.body;
  
  // Check if user already exists
  if (users.find(u => u.email === email || u.phone === phone)) {
    return res.status(400).json({ message: 'User already exists' });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { id: users.length + 1, name, email, phone, password: hashedPassword };
  users.push(newUser);
  
  const token = generateToken(newUser);
  res.status(201).json({ token });
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }
  
  const token = generateToken(user);
  res.json({ token });
});

// GitHub OAuth route
app.get('/auth/github', (req, res) => {
  // Redirect to GitHub OAuth flow
  res.redirect(`https://github.com/login/oauth/authorize?client_id=${process.env.GITHUB_CLIENT_ID}`);
});

app.get('/auth/github/callback', async (req, res) => {
  const { code } = req.query;
  // Exchange code for access token and get user info
  // Create or update user in database
  // Generate and send JWT
});

// Twilio verification route
app.post('/verify', (req, res) => {
  const { phone } = req.body;
  twilioClient.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID)
    .verifications
    .create({ to: phone, channel: 'sms' })
    .then(() => res.json({ message: 'Verification code sent' }))
    .catch(err => res.status(400).json({ message: err.message }));
});

app.post('/verify/check', (req, res) => {
  const { phone, code } = req.body;
  twilioClient.verify.v2.services(process.env.TWILIO_VERIFY_SERVICE_SID)
    .verificationChecks
    .create({ to: phone, code })
    .then(check => {
      if (check.status === 'approved') {
        // Create or update user in database
        // Generate and send JWT
        res.json({ message: 'Phone verified successfully' });
      } else {
        res.status(400).json({ message: 'Invalid verification code' });
      }
    })
    .catch(err => res.status(400).json({ message: err.message }));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
