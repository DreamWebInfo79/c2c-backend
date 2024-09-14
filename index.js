const serverless = require('serverless-http');
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid'); 
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
require('dotenv').config(); 

const app = express();

// Middleware to parse JSON request bodies
app.use(bodyParser.json());

// Connect to MongoDB using the URI from the environment variables
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Define Admin schema
const adminSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  uniqueId: { type: String, unique: true } // Unique UUID
});


const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true }, // Changed from `username` to `email`
  password: { type: String },
  uniqueId: { type: String, unique: true }, // Unique ID for user
  otp: String, // OTP for verification
  otpExpiry: Date, // Expiry time for OTP
  isVerified: { type: Boolean, default: false } // To track if the user is verified
});

// const userSchema = new mongoose.Schema({
//   email: { type: String, unique: true, required: true }, // Changed from `username` to `email`
//   password: { type: String, required: true },
//   uniqueId: { type: String, unique: true }, // Unique ID for user
//   otp: String, // OTP for verification
//   otpExpiry: Date, // Expiry time for OTP
//   isVerified: { type: Boolean, default: false } // To track if the user is verified
// });



// Define the Car schema
const carSchema = new mongoose.Schema({
  brand: String,
  model: String,
  year: String,
  price: String,
  kmDriven: String,
  fuelType: String,
  transmission: String,
  condition: String,
  location: String,
  images: [String],
  features: [
    {
      icon: String,
      label: String
    }
  ],
  technicalSpecifications: [
    {
      label: String,
      value: String
    }
  ]
});

// Create a Car model
const Car = mongoose.model('Car', carSchema);


// Create models for admins and users
const Admin = mongoose.model('Admin', adminSchema);
const User = mongoose.model('User', userSchema);

// Middleware for authenticating via uniqueId
const authenticateUniqueId = (req, res, next) => {
  const uniqueId = req.body;
  if (!uniqueId) {
    return res.status(401).json({ error: 'Missing unique ID' });
  }
  req.uniqueId = uniqueId;
  next();
};

// Create a Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail', // or your email provider
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Route to register a new admin
app.post('/admin/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const uniqueId = uuidv4(); // Generate UUID
    const newAdmin = new Admin({ username, password: hashedPassword, uniqueId });
    await newAdmin.save();
    res.status(201).json({ message: 'Admin registered successfully!', uniqueId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to register admin' });
  }
});

// Route to edit admin details (protected for admins only)
app.put('/admin/:id', authenticateUniqueId, async (req, res) => {
  const { uniqueId } = req.body;
  const { id } = req.params;
  const { username, password } = req.body;

  try {
    // Check if the request comes from an authorized admin
    const admin = await Admin.findOne({ uniqueId });
    if (!admin) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Check if the admin is attempting to edit the top admin
    const topAdmin = await Admin.findOne({ isTopAdmin: true });
    if (id === topAdmin._id.toString()) {
      return res.status(403).json({ error: 'Cannot edit top admin' });
    }

    const updateData = {};

    if (username) {
      updateData.username = username;
    }

    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    }

    // Find the admin by ID and update it
    const updatedAdmin = await Admin.findByIdAndUpdate(id, updateData, { new: true });

    if (!updatedAdmin) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    // Respond with the updated admin details
    res.status(200).json({ message: 'Admin updated successfully!', admin: updatedAdmin });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update admin' });
  }
});


// Route to delete admin (protected for admins only)
app.delete('/admin/:id', authenticateUniqueId, async (req, res) => {
  const { uniqueId } = req.body;
  const { id } = req.params;

  try {
    // Check if the request comes from an authorized admin
    const admin = await Admin.findOne({ uniqueId });
    if (!admin) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Check if the admin is attempting to delete the top admin
    const topAdmin = await Admin.findOne({ isTopAdmin: true });
    if (id === topAdmin._id.toString()) {
      return res.status(403).json({ error: 'Cannot delete top admin' });
    }

    // Find and delete the admin by ID
    const deletedAdmin = await Admin.findByIdAndDelete(id);

    if (!deletedAdmin) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    // Respond with a success message
    res.status(200).json({ message: 'Admin deleted successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete admin' });
  }
});

// Route to register a new top admin
app.post('/admin/register/top', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const uniqueId = uuidv4(); // Generate UUID
    const newAdmin = new Admin({ username, password: hashedPassword, uniqueId, isTopAdmin: true });
    await newAdmin.save();
    res.status(201).json({ message: 'Top admin registered successfully!', uniqueId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to register top admin' });
  }
});


// Route to log in as admin
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const admin = await Admin.findOne({ username });
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    res.json({ message: 'Login successful!', uniqueId: admin.uniqueId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

app.post('/user/request-otp', async (req, res) => {
  const { email } = req.body;

  try {
    const otp = crypto.randomInt(100000, 999999).toString(); // Generate 6-digit OTP
    const otpExpiry = new Date(Date.now() + 15 * 60 * 1000); // Set expiry time (15 minutes)

    // Check if user already exists
    let user = await User.findOne({ email });
    console.log(user)
    
    if (user && user.isVerified) {
      return res.status(400).json({ error: 'User already registered' });
    }

    if (!user) {
      // Create a new user with OTP and set as unverified
      user = new User({ email, otp, otpExpiry, isVerified: false });
    } else {
      // Update OTP and expiry for existing user
      user.otp = otp;
      user.otpExpiry = otpExpiry;
    }

    await user.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP code is ${otp}. It will expire in 15 minutes.`
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'OTP sent successfully!' });
  } catch (err) {
    console.error('Error sending OTP:', err);
    // console.log(err)
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});



app.post('/user/register', async (req, res) => {
  const { email, password, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    // if (!user) {
    //   return res.status(400).json({ error: 'User not found' });
    // }

    console.log('Received OTP:', otp);
    console.log('Stored OTP:', user.otp);
    console.log('OTP Expiry Time:', user.otpExpiry);
    console.log('Current Time:', new Date());

    // Check if OTP is correct and not expired
    if (!user.otp || user.otp !== otp || user.otpExpiry < Date.now()) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Hash password and update user details
    const hashedPassword = await bcrypt.hash(password, 10);
    const uniqueId = uuidv4(); // Generate UUID

    user.password = hashedPassword;
    user.uniqueId = uniqueId;
    user.isVerified = true; // Mark user as verified
    user.otp = null; // Clear OTP
    user.otpExpiry = null; // Clear OTP expiry time

    await user.save();
    res.status(201).json({ message: 'User registered successfully!', uniqueId });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ error: 'Failed to register user' });
  }
});


// Route to request password reset OTP
app.post('/user/request-reset', async (req, res) => {
  const { email } = req.body;

  try {
    const otp = crypto.randomInt(100000, 999999).toString(); // Generate 6-digit OTP
    const otpExpiry = new Date(Date.now() + 15 * 60 * 1000); // Set expiry time (15 minutes)

    const user = await User.findOne({ username: email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update OTP and expiry for user
    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    const mailOptions = {
      from: 'your-email@gmail.com',
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP code for password reset is ${otp}. It will expire in 15 minutes.`
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'OTP sent successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Route to reset password
app.post('/user/reset-password', async (req, res) => {
  const { email, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ username: email });

    if (!user || user.otp !== otp || user.otpExpiry < Date.now()) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    // Hash new password and update user details
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.otp = null; // Clear OTP
    user.otpExpiry = null; // Clear OTP expiry time

    await user.save();
    res.status(200).json({ message: 'Password reset successfully!' });
  } catch (err) {
    console.error('Error resetting password:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Route to log in as user
app.post('/user/login', async (req, res) => {
  const { email, password } = req.body; // Changed from `username` to `email`

  try {
    // Find user by email
    const user = await User.findOne({ email });

    // If user doesn't exist or password doesn't match
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // If login is successful
    res.json({ message: 'Login successful!', uniqueId: user.uniqueId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to log in' });
  }
});


// Route to save car data (protected for admins only)
// Route to save car data (protected for admins only)
app.post('/cars', authenticateUniqueId, async (req, res) => {
  const { uniqueId } = req.body;

  try {
    // Check if the request comes from an authorized admin
    const admin = await Admin.findOne({ uniqueId });
    if (!admin) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Extract car data from the request body
    const { cars } = req.body;

    // Validate if cars data is present
    if (!cars || !Array.isArray(cars)) {
      return res.status(400).json({ error: 'Invalid data format' });
    }

    // Save each car in the database
    const savedCars = await Promise.all(
      cars.map(async (carData) => {
        const newCar = new Car(carData);
        return await newCar.save();
      })
    );

    // Respond with a success message
    res.status(201).json({ message: 'Cars saved successfully!', cars: savedCars });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save cars' });
  }
});

// Route to edit car data (protected for admins only)
app.put('/cars/:id', authenticateUniqueId, async (req, res) => {
  const { uniqueId } = req.body;
  const { id } = req.params;
  const updateData = req.body;

  try {
    // Check if the request comes from an authorized admin
    const admin = await Admin.findOne({ uniqueId });
    if (!admin) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Find the car by ID and update it
    const updatedCar = await Car.findByIdAndUpdate(id, updateData, { new: true });

    if (!updatedCar) {
      return res.status(404).json({ error: 'Car not found' });
    }

    // Respond with the updated car details
    res.status(200).json({ message: 'Car updated successfully!', car: updatedCar });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to update car' });
  }
});


// Route to delete car data (protected for admins only)
app.delete('/cars/:id', authenticateUniqueId, async (req, res) => {
  const { uniqueId } = req.body;
  const { id } = req.params;

  try {
    // Check if the request comes from an authorized admin
    const admin = await Admin.findOne({ uniqueId });
    if (!admin) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Find and delete the car by ID
    const deletedCar = await Car.findByIdAndDelete(id);

    if (!deletedCar) {
      return res.status(404).json({ error: 'Car not found' });
    }

    // Respond with a success message
    res.status(200).json({ message: 'Car deleted successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to delete car' });
  }
});



// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

module.exports.app = serverless(app);
