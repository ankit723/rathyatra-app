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

const User = mongoose.model('User', userSchema);

const generateAccessToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

const generateRefreshToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '30d' });
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
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, email, password: hashedPassword, rank, permanentAddress, currentAddress, phoneNumber, currentLocation, assignedLocation, age, sex });
    await user.save();
    res.status(201).json({ message: 'User registered successfully', accessToken: generateAccessToken(user._id), refreshToken: generateRefreshToken(user._id), user: user });
});


//login route
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });
    const isPasswordValid = await bcrypt.compare(password, user.password);  
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid email or password' });
    res.status(200).json({ message: 'Login successful', accessToken: generateAccessToken(user._id), refreshToken: generateRefreshToken(user._id), user: user });
});


//refresh token route
app.post('/auth/refresh-token', (req, res) => {
    const { refreshToken } = req.body;
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const accessToken = generateAccessToken(decoded.userId);
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

//update assigned location using auth token
app.put('/auth/update-assigned-location', async (req, res) => {
    const refreshToken = req.headers.authorization;
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    user.assignedLocation = req.body.assignedLocation;
    await user.save();
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
app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});