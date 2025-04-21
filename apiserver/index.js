import dotenv from 'dotenv'
dotenv.config();
import express from "express"
import cors from 'cors'
import bodyParser from "body-parser"
import mongoose from "mongoose"
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

const app = express();

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => {
    console.log("Connected to MongoDB");
})
.catch((err) => {
    console.log(err);
});


const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: String,
    password: String,
    rank: String,
    permanentAddress: String,
    currentAddress: String,
    phoneNumber: String, 
    currentLocation: {type: String, default: "Not Assigned"},
    assignedLocation: {type: String, default: "Not Assigned"},
    atAssignedLocation: {type: Boolean, default: false},
    emergencyAlarm: {type: Boolean, default: false},
    age: Number,
    sex: String,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
});

const adminSchema = new mongoose.Schema({
    email: String,
    password: String,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);

const generateAccessToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

const generateRefreshToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '30d' });
}

const generateAdminAccessToken = (adminId) => {
    return jwt.sign({ adminId }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

const generateAdminRefreshToken = (adminId) => {
    return jwt.sign({ adminId }, process.env.JWT_SECRET, { expiresIn: '30d' });
}

//logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

//health check route
app.get('/health', (req, res) => {
    res.status(200).json({ message: 'Server is running' });
});

//register route
app.post('/auth/register', async (req, res) => {
    const { firstName, lastName, email, password, rank, permanentAddress, currentAddress, phoneNumber, currentLocation, assignedLocation, age, sex } = req.body;
    if (!firstName || !lastName || !email || !password || !rank || !permanentAddress || !currentAddress || !phoneNumber || !currentLocation || !assignedLocation || !age || !sex) {
        return res.status(400).json({ message: 'All fields are required' });
    }
    const existingUser = await User.findOne({ phoneNumber });
    if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, email, password: hashedPassword, rank, permanentAddress, currentAddress, phoneNumber, currentLocation, assignedLocation, age, sex });
    await user.save();
    res.status(201).json({ message: 'User registered successfully', accessToken: generateAccessToken(user._id), refreshToken: generateRefreshToken(user._id), user: user });
});


//login route
app.post('/auth/login', async (req, res) => {
    const { phoneNumber, password } = req.body;
    const user = await User.findOne({ phoneNumber });
    if (!user) return res.status(401).json({ message: 'Invalid phone number or password' });
    const isPasswordValid = await bcrypt.compare(password, user.password);  
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid phone number or password' });
    res.status(200).json({ message: 'Login successful', accessToken: generateAccessToken(user._id), refreshToken: generateRefreshToken(user._id), user: user });
});


//refresh token route
app.post('/auth/refresh-token', (req, res) => {
    const { refreshToken } = req.body;
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const accessToken = generateAccessToken(decoded.userId);
    res.status(200).json({ accessToken });
});

//admin login route
app.post('/auth/admin/login', async (req, res) => {
    const { email, password } = req.body;
    const admin = await Admin.findOne({ email });
    if (!admin) return res.status(401).json({ message: 'Invalid email or password' });
    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid email or password' });
    res.status(200).json({ message: 'Login successful', accessToken: generateAdminAccessToken(admin._id), refreshToken: generateAdminRefreshToken(admin._id), admin: admin });
}); 

//admin register route
app.post('/auth/admin/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const admin = new Admin({ email, password: hashedPassword });
    await admin.save();
    res.status(201).json({ message: 'Admin registered successfully', accessToken: generateAdminAccessToken(admin._id), refreshToken: generateAdminRefreshToken(admin._id), admin: admin });
});

//admin refresh token route
app.post('/auth/admin/refresh-token', (req, res) => {
    const { refreshToken } = req.body;
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const accessToken = generateAdminAccessToken(decoded.adminId);
    res.status(200).json({ accessToken });
});


//get assigned location using auth token
app.get('/auth/assigned-location', async (req, res) => {
    const refreshToken = req.headers.authorization;
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    res.status(200).json({ assignedLocation: user.assignedLocation });
});

//get current location using auth token
app.get('/auth/current-location', async (req, res) => {
    const refreshToken = req.headers.authorization;
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    res.status(200).json({ currentLocation: user.currentLocation });
});


//update current location
app.put('/auth/update-location', async (req, res) => {
    const refreshToken = req.headers.authorization;
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    user.currentLocation = req.body.currentLocation;
    await user.save();
    res.status(200).json({ message: 'Current location updated successfully' });
});

// update at assigned location
app.put('/auth/update-at-assigned-location', async (req, res) => {
    const refreshToken = req.headers.authorization;
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    user.atAssignedLocation = req.body.atAssignedLocation;
    await user.save();
    res.status(200).json({ message: 'At assigned location updated successfully' });
});

//emergency alarm route
app.put('/auth/emergency-alarm', async (req, res) => {
    const refreshToken = req.headers.authorization;
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    user.emergencyAlarm = true;
    await user.save();
    res.status(200).json({ message: 'Emergency alarm updated successfully' });
});

//get all users
app.get('/users', async (req, res) => {
    const users = await User.find();
    res.status(200).json({ users });
});

//get user by id
app.get('/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    res.status(200).json({ user });
});

//update user by id
app.put('/users/:id', async (req, res) => {
    const user = await User.findById(req.params.id);
    
    // Update all fields from request body
    const { firstName, lastName, email, rank, permanentAddress, currentAddress, phoneNumber, age, sex } = req.body;
    
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (email) user.email = email;
    if (rank) user.rank = rank;
    if (permanentAddress !== undefined) user.permanentAddress = permanentAddress;
    if (currentAddress !== undefined) user.currentAddress = currentAddress;
    if (phoneNumber) user.phoneNumber = phoneNumber;
    if (age !== undefined) user.age = age;
    if (sex) user.sex = sex;
    
    // Update timestamp
    user.updatedAt = Date.now();
    
    await user.save();
    res.status(200).json({ message: 'User updated successfully', user });
});

//update assigned location 
app.put('/users/:id/assigned-location', async (req, res) => {
    const user = await User.findById(req.params.id);
    user.assignedLocation = req.body.assignedLocation;
    await user.save();
    res.status(200).json({ message: 'Assigned location updated successfully' });
});

//get user current location
app.get('/users/:id/current-location', async (req, res) => {
    const user = await User.findById(req.params.id);
    res.status(200).json({ currentLocation: user.currentLocation });
});

//get user locations (both current and assigned)
app.get('/users/:id/locations', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.status(200).json({ 
            currentLocation: user.currentLocation,
            assignedLocation: user.assignedLocation,
            atAssignedLocation: user.atAssignedLocation
        });
    } catch (err) {
        console.error('Error fetching user locations:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// get all admins
app.get('/admins', async (req, res) => {
    const admins = await Admin.find();
    res.status(200).json({ admins });
});

//get admin by id
app.get('/admins/:id', async (req, res) => {
    const admin = await Admin.findById(req.params.id);
    res.status(200).json({ admin });
});

//update admin by id
app.put('/admins/:id', async (req, res) => {
    const admin = await Admin.findById(req.params.id);
    admin.email = req.body.email;
    await admin.save();
    res.status(200).json({ message: 'Admin updated successfully', admin });
});

//delete admin by id
app.delete('/admins/:id', async (req, res) => {
    await Admin.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: 'Admin deleted successfully' });
});





app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});