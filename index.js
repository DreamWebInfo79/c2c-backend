const serverless = require('serverless-http');
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
// const bcrypt = require('bcrypt');/
const bcrypt = require('bcryptjs');

const GoogleStrategy = require('passport-google-oauth20')
const passport = require('passport');
const session = require('express-session');

const { v4: uuidv4 } = require('uuid'); 
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const { Schema } = mongoose;
require('dotenv').config(); 
const app = express();

app.use(cors());

app.use(cors({
  origin: '*', 
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));

app.use(express.json()); 

const secret = crypto.randomBytes(32).toString('hex');

app.use(session({ secret: secret, resave: false, saveUninitialized: true }));

app.use(express.urlencoded({extended: true}));
app.use(bodyParser.json());
app.use(passport.initialize());
app.use(passport.session());

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
  email: { type: String, unique: true },
  password: String,
  uniqueId: { type: String, unique: true }, // Unique UUID
  isTopAdmin: { type: Boolean, default: false } ,
  createdAt: { type: Date, default: Date.now }
});

const carSchema = new mongoose.Schema({
  carId: { type: String, unique: true, required: true },
  brand: { type: String, required: true },
  model: { type: String, required: true },
  year: { type: String, required: true },
  price: { type: String, required: true },
  paragraph: {type: String, required:true},
  kmDriven: { type: String, required: true },
  fuelType: { type: String, required: true },
  transmission: { type: String, required: true },
  condition: { type: String, required: true },
  location: { type: String, required: true },
  images: {
    type: [String],
    default: []
  },
  features: [
    {
      icon: { type: String },
      label: { type: String }
    }
  ],
  technicalSpecifications: [
    {
      label: { type: String },
      value: { type: String }
    }
  ]
});


const userSchema = new mongoose.Schema({
  email: { type: String, unique: true }, // Changed from `username` to `email`
  password: { type: String },
  uniqueId: { type: String, unique: true }, // Unique ID for user
  otp: String, // OTP for verification
  otpExpiry: Date, // Expiry time for OTP
  isVerified: { type: Boolean, default: false },
  favorites: [carSchema]
});

const userCarSchema = new mongoose.Schema({
  username: { type: String, required: true },
  phoneNumber: { type: String, required: true },
  contactId : { type: String, required: true },
  carName: { type: String, required: true },
  status: { type: String, default: 'pending' }, 
  currentTime: { type: Date, default: Date.now },// e.g. 'booked', 'completed'
}, { timestamps: true });

const CarBooking = mongoose.model('CarBooking', userCarSchema);



// Create models
const Car = mongoose.model('Car', carSchema);

// Create a Car model
// const Car = mongoose.model('Car', carSchema);


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

// Middleware to authenticate user (example, you can adjust this)
const authenticateUser = (req, res, next) => {
  const uniqueId = req.body;
  // Mock authentication check (assuming user ID comes from JWT or session)
  if (!uniqueId) return res.status(401).json({ error: 'Unauthorized' });
  next();
};


passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
},
async (accessToken, refreshToken, profile, done) => {
  try {
    // Find user by email
    let user = await User.findOne({ email: profile.emails[0].value });

    if (!user) {
      const uniqueId = generateUniqueId();
      user = new User({
        email: profile.emails[0].value,
        uniqueId: uniqueId,
        isVerified: true, // Google users are verified
        favorites: [], // Initialize empty favorites
      });
      await user.save();
    }

    // Return only the uniqueId in the done callback
    return done(null, { uniqueId: user.uniqueId, email:profile.emails[0].value, favorites: user.favorites });
  } catch (err) {
    return done(err, null);
  }
}
));

passport.serializeUser((user, done) => {
  // Serialize only the uniqueId
  done(null, { uniqueId: user.uniqueId });
});

passport.deserializeUser((obj, done) => {
  // Deserialize only the uniqueId
  done(null, obj);
});




// google login 


app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.post('/auth/google/callback', async (req, res) => {
  const { token } = req.body;

  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    // Find user by email
    let user = await User.findOne({ email: payload.email });

    if (!user) {
      const uniqueId = generateUniqueId();
      user = new User({
        email: payload.email,
        uniqueId: uniqueId,
        isVerified: true, // Google users can be marked as verified
        favorites: [], // Initialize empty favorites list
      });
      await user.save();
    }

    // Send only the uniqueId in the response
    req.login(user, (err) => {
      if (err) {
        return res.status(500).send(err);
      }
      res.status(200).json({ uniqueId: user.uniqueId });
    });
  } catch (error) {
    console.error('Error processing login:', error);
    res.status(500).send({ message: 'Error processing login' });
  }
});












// Route to register a new admin
app.post('/admin/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const uniqueId = uuidv4(); // Generate UUID
    const newAdmin = new Admin({ email, password: hashedPassword, uniqueId });
    await newAdmin.save();
    res.status(201).json({ message: 'Admin registered successfully!', uniqueId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to register admin' });
  }
});

// Route to get all the admin data 
app.get('/admin/all', async (req, res) => {
  try {
    // Find all admin data
    const admins = await Admin.find({ isTopAdmin: { $ne: true } });
    // const admins = await Admin.find({});

    // Return the data
    res.json(admins);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch admin data' });
  }
});


// Route to edit admin details (protected for admins only)
app.put('/admin/:id', authenticateUniqueId, async (req, res) => {
  const { id } = req.params; // This is the ID of the admin to be updated
  const { email, password, uniqueId } = req.body; // This is the ID of the admin making the request


  try {
    // Check if the request comes from an authorized admin
    const admin = await Admin.findOne({ uniqueId });
    if (!admin) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Check if the admin is attempting to edit the top admin
    const topAdmin = await Admin.findOne({ isTopAdmin: true });
    if (id === topAdmin.uniqueId) {
      return res.status(403).json({ error: 'Cannot edit top admin' });
    }

    const updateData = {};

    if (email) {
      updateData.email = email;
    }

    if (password) {
      updateData.password = await bcrypt.hash(password, 10);
    }

    // Find the admin by ID and update it
    const updatedAdmin = await Admin.findOneAndUpdate({ uniqueId: id }, updateData, { new: true });

    if (!updatedAdmin) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    res.status(200).json({ message: 'Admin updated successfully!' });
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
    if (id === topAdmin.uniqueId) {
      return res.status(403).json({ error: 'Cannot delete top admin' });
    }

    // Find and delete the admin by uniqueId
    const deletedAdmin = await Admin.findOneAndDelete({ uniqueId: id });

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
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const uniqueId = uuidv4(); // Generate UUID
    const newAdmin = new Admin({ email, password: hashedPassword, uniqueId, isTopAdmin: true });
    await newAdmin.save();
    res.status(201).json({ message: 'Top admin registered successfully!', uniqueId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to register top admin' });
  }
});


// Route to log in as admin
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const admin = await Admin.findOne({ email });
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    console.log(admin);
    res.json({ message: 'Login successful!', uniqueId: admin.uniqueId, role: 'admin' });
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
      subject: 'Your OTP Code - cars2customer',
      text: `Dear Customer,

      Thank you for choosing cars2customer! 

      Your OTP code is ${otp}. Please use this code to complete your verification process. It will expire in 15 minutes, so be sure to enter it promptly.

      If you did not request this code, please contact our support team immediately.

      We appreciate your trust in us to help you find the best vehicles suited to your needs. 

      Best regards,
      The cars2customer Team
      `
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
    res.status(201).json({ message: 'User registered successfully!', uniqueId,  favorites: user.favorites});
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

    const user = await User.findOne({ email: email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update OTP and expiry for user
    user.otp = otp;
    user.otpExpiry = otpExpiry;
    await user.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP - cars2customer',
      text: `Dear Customer,

      It looks like you requested to reset your password for your cars2customer account. 

      Your OTP code is ${otp}. Please use this code to complete the password reset process. It will expire in 15 minutes, so be sure to enter it promptly.

      If you did not request this code, please contact our support team immediately.

      We take your security seriously and are here to help if you need any assistance.

      Best regards,
      The cars2customer Team
      `
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
    const user = await User.findOne({ email: email });

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
    res.json({ message: 'Login successful!', uniqueId: user.uniqueId, favorites: user.favorites });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

// Route to get all cars (accessible to everyone)
app.get('/all-cars', async (req, res) => {
  try {
    // Fetch all cars from the database
    const cars = await Car.find();

    // Format the cars data by brand
    const carsByBrand = cars.reduce((acc, car) => {
      if (!acc[car.brand]) {
        acc[car.brand] = [];
      }
      acc[car.brand].push(car);
      return acc;
    }, {});

    // Respond with the formatted car data
    res.status(200).json({ cars: carsByBrand });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to retrieve cars' });
  }
});


// Route to get only one car data based on the params id 

// Route to get a single car by ID
app.get('/cars/:id', async (req, res) => {
  const { id } = req.params;

  try {
    // Find the car by ID
    const car = await Car.findOne({ carId: id });

    // If car is not found
    if (!car) {
      return res.status(404).json({ error: 'Car not found' });
    }

    // Respond with the car details
    res.status(200).json({ car });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to retrieve car' });
  }
});





// Route to save car data (protected for admins only)
app.post('/cars', authenticateUniqueId, async (req, res) => {
  const { uniqueId, car } = req.body;

  try {
    // Check if the request comes from an authorized admin
    const admin = await Admin.findOne({ uniqueId });
    if (!admin) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Validate if the car data is present
    if (!car || typeof car !== 'object') {
      return res.status(400).json({ error: 'Invalid data format' });
    }

    // Create a new car document
    const newCar = new Car(car);
    const savedCar = await newCar.save();

    // Respond with a success message
    res.status(201).json({ message: 'Car added successfully!', car: savedCar });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to add car' });
  }
});


// Route to edit car data (protected for admins only)
app.put('/cars/:carId', authenticateUniqueId, async (req, res) => {
  const { uniqueId } = req.body; // Extract uniqueId from the body
  const { carId } = req.params; // Extract carId from the URL parameters
  const updateData = req.body.updateData; // Extract update data from the body

  try {
    // Check if the request comes from an authorized admin
    const admin = await Admin.findOne({ uniqueId });
    if (!admin) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Find the car by custom carId and update it
    const updatedCar = await Car.findOneAndUpdate({ carId: carId }, updateData, { new: true });

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
// Route to delete a car (protected for admins only)
app.delete('/cars/:carId', authenticateUniqueId, async (req, res) => {
  const { uniqueId } = req.body; // Extract uniqueId from the body
  const { carId } = req.params; // Extract carId from the URL parameters

  try {
    // Check if the request comes from an authorized admin
    const admin = await Admin.findOne({ uniqueId });
    if (!admin) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    // Find and delete the car by custom carId
    const deletedCar = await Car.findOneAndDelete({ carId: carId });

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


//favourite
app.post('/favorites/add', authenticateUser, async (req, res) => {
  const { carId, uniqueId } = req.body; // carId and uniqueId are expected in the request body

  try {
    // Find the user
    const user = await User.findOne({ uniqueId: uniqueId });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Find the car by carId
    const car = await Car.findOne({ carId: carId });
    if (!car) return res.status(404).json({ error: 'Car not found' });

    // Check if the car is already in the user's favorites
    const carExists = user.favorites.some(fav => fav.carId === carId);
    console.log(carExists)
    if (carExists) return res.status(400).json({ error: 'Car is already in favorites' });
    // Add the car details to the user's favorites
    user.favorites.push(car);
    await user.save();

    return res.status(200).json({ message: 'Car added to favorites', favorites: user.favorites });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Remove a car from the favorite list
app.post('/favorites/remove', authenticateUser, async (req, res) => {
  const { carId, uniqueId } = req.body;

  try {
    // Find the user
    const user = await User.findOne({ uniqueId });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Check if the car is in the user's favorites
    const carIndex = user.favorites.findIndex(fav => fav.carId === carId);
    if (carIndex === -1) return res.status(400).json({ error: 'Car not found in favorites' });

    // Remove the car from the favorites list
    user.favorites.splice(carIndex, 1);
    await user.save();

    return res.status(200).json({ message: 'Car removed from favorites', favorites: user.favorites });
  } catch (error) {
    console.error('Error removing car from favorites:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});



app.get('/car/favorites/:uniqueId', async (req, res) => {
  const uniqueId = req.params.uniqueId;

  try {
      // Find the user by uniqueId
      const user = await User.findOne({ uniqueId: uniqueId });
      if (!user) return res.status(404).json({ error: 'User not found' });

      // Return the user's favorite cars
      return res.status(200).json({ favorites: user.favorites });
  } catch (error) {
      console.error('Error retrieving favorites:', error);
      return res.status(500).json({ error: 'Server error' });
  }
});
``
//route used for car booking 
app.post('/cars/bookings', async (req, res) => {
  const { username, phoneNumber, contactId, carName, status } = req.body;
  console.log(username, phoneNumber, contactId, carName, status);
  try {

    const newBooking = new CarBooking({
      username,
      phoneNumber,
      contactId,
      carName,
      status: status || 'pending',
    });

    const savedBooking = await newBooking.save();
    res.status(201).json(savedBooking);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get all bookings
app.get('/carsBooked/bookings', async (req, res) => {
  try {
    const bookings = await CarBooking.find();
    res.status(200).json(bookings);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Get a single booking by ID
app.get('/cars/bookings/:id', async (req, res) => {
  try {
    const booking = await CarBooking.findById(req.params.id);

    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    res.status(200).json(booking);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.put('/carsBooked/bookings/:carId', async (req, res) => {
  try {
    const {carId } = req.params;
    const {  status } = req.body; // Extract carId and status from the body

    // Check if carId and status are provided
    if (!carId || !status) {
      return res.status(400).json({ message: 'carId and status are required' });
    }

    // Update the booking by carId
    const updatedBooking = await CarBooking.findOneAndUpdate(
      { carId: carId }, // Find by carId
      { status }, // Update only the status
      { new: true, runValidators: true }
    );

    if (!updatedBooking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    res.status(200).json(updatedBooking);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});




app.delete('/carsBooked/bookings/:carId', async (req, res) => {
  try {
    const { carId } = req.params; // Extract carId from the request body

    // Check if carId is provided
    if (!carId) {
      return res.status(400).json({ message: 'carId is required' });
    }

    const deletedBooking = await CarBooking.findOneAndDelete({ carId }); // Find by carId

    if (!deletedBooking) {
      return res.status(404).json({ message: 'Booking not found' });
    }

    res.status(200).json({ message: 'Booking deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});


// Start the server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

// module.exports.app = serverless(app);

const handler = serverless(app);

exports.handler = async (event, context) => {
  return handler(event, context);
};