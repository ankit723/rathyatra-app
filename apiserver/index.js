import dotenv from 'dotenv'
dotenv.config();
import express from "express"
import cors from 'cors'
import bodyParser from "body-parser"
import mongoose from "mongoose"
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { Client } from '@googlemaps/google-maps-services-js'

const app = express();

const corsOptions = {
    origin: ['http://localhost:3000', 'https://rathyatra-admin.vercel.app', 'https://puripolice.in'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  };
  
app.use(cors(corsOptions));

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
    assignedGeoFenceRadius: {type: Number, default: 200},
    currentLocation: {type: String, default: "Not Assigned"},
    assignedLocation: {type: String, default: "Not Assigned"},
    atAssignedLocation: {type: Boolean, default: false},
    emergencyAlarm: {type: Boolean, default: false},
    age: Number,
    sex: String,
    messages: [{
        content: String,
        sentBy: {
            adminId: String,
            adminEmail: String
        },
        mediaUrls: [{ type: String }],
        sentAt: { type: Date, default: Date.now },
        read: { type: Boolean, default: false }
    }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
});

const adminSchema = new mongoose.Schema({
    email: String,
    password: String,
    sentMessages: [{
        content: String,
        sentTo: [{
            userId: String,
            firstName: String,
            lastName: String
        }],
        mediaUrls: [{ type: String }],
        sentAt: { type: Date, default: Date.now }
    }],
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
    let { firstName, lastName, password, rank, permanentAddress, currentAddress, phoneNumber, assignedLocation, age, sex } = req.body;
    if (!firstName || !lastName || !password || !rank || !permanentAddress || !currentAddress || !phoneNumber || !assignedLocation || !age || !sex) {
        return res.status(400).json({ message: 'All fields are required' });
    }

    //check valid phone number
    if (!/^\+91\d{10}$/.test(phoneNumber)) {
        return res.status(400).json({ message: 'Invalid phone number' });
    }

    phoneNumber = phoneNumber.trim();

    const existingUser = await User.findOne({ phoneNumber });
    if (existingUser) {
        return res.status(400).json({ message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, password: hashedPassword, rank, permanentAddress, currentAddress, phoneNumber, assignedLocation, age, sex });
    await user.save();
    res.status(201).json({ message: 'User registered successfully', accessToken: generateAccessToken(user._id), refreshToken: generateRefreshToken(user._id), user: user });
});


app.post('/auth/login', async (req, res) => {
    let { phoneNumber, password } = req.body;

    //check valid phone number
    if (!/^\+91\d{10}$/.test(phoneNumber)) {
        return res.status(400).json({ message: 'Invalid phone number' });
    }

    phoneNumber = phoneNumber.trim();

    const user = await User.findOne({ phoneNumber });
    if (!user) return res.status(401).json({ message: 'Invalid phone number or password' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid phone number or password' });

    res.status(200).json({
        message: 'Login successful',
        accessToken: generateAccessToken(user._id),
        refreshToken: generateRefreshToken(user._id),
        user
    });
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
    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        
        // Check if admin still exists in the database
        Admin.findById(decoded.adminId).then(admin => {
            if (!admin) {
                return res.status(401).json({ message: 'Admin account no longer exists' });
            }
            const accessToken = generateAdminAccessToken(decoded.adminId);
            res.status(200).json({ accessToken });
        }).catch(err => {
            console.error('Error verifying admin:', err);
            res.status(401).json({ message: 'Authentication failed' });
        });
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(401).json({ message: 'Invalid refresh token' });
    }
});

// Middleware to verify admin token and ensure admin still exists
const verifyAdminToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Authorization token required' });
        }
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (!decoded.adminId) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        
        // Check if admin still exists in the database
        const admin = await Admin.findById(decoded.adminId);
        if (!admin) {
            return res.status(401).json({ message: 'Admin account no longer exists' });
        }
        
        // Add admin to request object
        req.admin = admin;
        next();
    } catch (error) {
        console.error('Admin auth error:', error);
        return res.status(401).json({ message: 'Authentication failed' });
    }
};

// Apply admin auth middleware to admin-only routes
app.get('/admin/validate-token', verifyAdminToken, (req, res) => {
    res.status(200).json({ 
        message: 'Token is valid',
        admin: {
            _id: req.admin._id,
            email: req.admin.email
        }
    });
});

// Secure all admin endpoints with the middleware
app.get('/admins', verifyAdminToken, async (req, res) => {
    const admins = await Admin.find();
    res.status(200).json({ admins });
});

//get admin by id
app.get('/admins/:id', verifyAdminToken, async (req, res) => {
    const admin = await Admin.findById(req.params.id);
    res.status(200).json({ admin });
});

//update admin by id
app.put('/admins/:id', verifyAdminToken, async (req, res) => {
    const admin = await Admin.findById(req.params.id);
    admin.email = req.body.email;
    await admin.save();
    res.status(200).json({ message: 'Admin updated successfully', admin });
});

//delete admin by id
app.delete('/admins/:id', verifyAdminToken, async (req, res) => {
    await Admin.findByIdAndDelete(req.params.id);
    res.status(200).json({ message: 'Admin deleted successfully' });
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
    let { firstName, lastName, rank, permanentAddress, currentAddress, phoneNumber, age, sex } = req.body;
    
    //check valid phone number
    if (!/^\+91\d{10}$/.test(phoneNumber)) {
        return res.status(400).json({ message: 'Invalid phone number' });
    }

    phoneNumber = phoneNumber.trim();
    
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
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

// Get messages for a user
app.get('/user/messages/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findById(userId);
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.status(200).json({ messages: user.messages });
    } catch (error) {
        console.error('Error retrieving messages:', error);
        res.status(500).json({ message: 'Failed to retrieve messages', error: error.message });
    }
});

// Get messages sent by an admin
app.get('/admin/messages/:adminId', verifyAdminToken, async (req, res) => {
    try {
        const { adminId } = req.params;
        const admin = await Admin.findById(adminId);
        
        if (!admin) {
            return res.status(404).json({ message: 'Admin not found' });
        }
        
        res.status(200).json({ messages: admin.sentMessages });
    } catch (error) {
        console.error('Error retrieving messages:', error);
        res.status(500).json({ message: 'Failed to retrieve messages', error: error.message });
    }
});

// Send message from admin to users
app.post('/admin/send-message', verifyAdminToken, async (req, res) => {
    try {
        const { message, userIds, adminId, mediaUrls } = req.body;
        
        if (!userIds || !userIds.length || !adminId) {
            return res.status(400).json({ message: 'Recipient user IDs and admin ID are required' });
        }

        if (!message && (!mediaUrls || mediaUrls.length === 0)) {
            return res.status(400).json({ message: 'Message content or media URLs are required' });
        }

        // Validate mediaUrls format (array of strings)
        if (mediaUrls && !Array.isArray(mediaUrls)) {
            return res.status(400).json({ message: 'mediaUrls must be an array' });
        }
        if (mediaUrls && mediaUrls.some(url => typeof url !== 'string')) {
            return res.status(400).json({ message: 'All mediaUrls must be strings' });
        }

        // Find the admin who's sending the message
        const admin = await Admin.findById(adminId);
        if (!admin) {
            return res.status(404).json({ message: 'Admin not found' });
        }

        // Verify that the requesting admin matches the sending admin
        if (req.admin._id.toString() !== adminId) {
            return res.status(403).json({ message: 'Unauthorized to send messages on behalf of another admin' });
        }

        // Find all users who will receive the message
        const users = await User.find({ _id: { $in: userIds } });
        if (!users.length) {
            return res.status(404).json({ message: 'No valid users found' });
        }

        // Prepare recipient data for admin record
        const recipients = users.map(user => ({
            userId: user._id,
            firstName: user.firstName,
            lastName: user.lastName
        }));

        // Add message to admin's sent messages
        admin.sentMessages.push({
            content: message,
            sentTo: recipients,
            mediaUrls: mediaUrls || [],
            sentAt: new Date()
        });
        
        await admin.save();

        // Add message to each user's messages
        const messageData = {
            content: message,
            sentBy: {
                adminId: admin._id,
                adminEmail: admin.email
            },
            mediaUrls: mediaUrls || [],
            sentAt: new Date()
        };

        // Update all users in parallel
        await Promise.all(users.map(user => {
            user.messages.push(messageData);
            return user.save();
        }));

        res.status(200).json({ 
            message: 'Message sent successfully',
            recipients: recipients.length
        });
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ message: 'Failed to send message', error: error.message });
    }
});

//resolve emergency
app.put('/users/:id/emergency', verifyAdminToken, async (req, res) => {
    const user = await User.findById(req.params.id);
    user.emergencyAlarm = false;
    await user.save();
    res.status(200).json({ message: 'Emergency resolved successfully' });
});

//delete user by id
app.delete('/users/:id', verifyAdminToken, async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.status(200).json({ message: 'User deleted successfully' });
    } catch (err) {
        console.error('Error deleting user:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

//update user password
app.put('/users/:id/password', verifyAdminToken, async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) {
            return res.status(400).json({ message: 'Password is required' });
        }
        
        const user = await User.findById(req.params.id);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.updatedAt = Date.now();
        await user.save();
        
        res.status(200).json({ message: 'Password updated successfully' });
    } catch (err) {
        console.error('Error updating password:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

//get assigned geo fence radius
app.get('/users/:id/assigned-geo-fence-radius', verifyAdminToken, async (req, res) => {
    console.log(req.params.id);
    const user = await User.findById(req.params.id);
    res.status(200).json({ assignedGeoFenceRadius: user.assignedGeoFenceRadius });
});

//update assigned geo fence radius
app.put('/users/:id/assigned-geo-fence-radius', verifyAdminToken, async (req, res) => {
    const user = await User.findById(req.params.id);
    user.assignedGeoFenceRadius = req.body.assignedGeoFenceRadius;
    await user.save();
    res.status(200).json({ message: 'Assigned geo fence radius updated successfully' });
});

// Search users by location (within specified radius)
app.get('/users/search/location', async (req, res) => {
    try {
        const { location, radius = 200 } = req.query;
        
        if (!location) {
            return res.status(400).json({ message: 'Location parameter is required' });
        }
        
        // Step 1: Fetch all users
        const allUsers = await User.find();
        
        // Step 2: Use Google Maps Geocoding API to get coordinates for the search location
        const client = new Client({});
        
        const geocodeResponse = await client.geocode({
            params: {
                address: location,
                key: process.env.GOOGLE_MAPS_API_KEY
            }
        });
        
        if (geocodeResponse.data.status !== 'OK' || geocodeResponse.data.results.length === 0) {
            return res.status(400).json({ message: 'Could not geocode the provided location' });
        }
        
        const searchLocation = geocodeResponse.data.results[0].geometry.location;
        const searchLatLng = { lat: searchLocation.lat, lng: searchLocation.lng };
        
        // Step 3: Filter users based on distance to search location
        const usersWithinRadius = [];
        
        for (const user of allUsers) {
            // Skip users without a current location
            if (!user.currentLocation || user.currentLocation === 'Not Assigned') {
                continue;
            }
            
            try {
                // Geocode the user's current location
                const userGeocodeResponse = await client.geocode({
                    params: {
                        address: user.currentLocation,
                        key: process.env.GOOGLE_MAPS_API_KEY
                    }
                });
                
                if (userGeocodeResponse.data.status === 'OK' && userGeocodeResponse.data.results.length > 0) {
                    const userLocation = userGeocodeResponse.data.results[0].geometry.location;
                    const userLatLng = { lat: userLocation.lat, lng: userLocation.lng };
                    
                    // Calculate distance between search location and user location
                    const distance = calculateDistance(
                        searchLatLng.lat, searchLatLng.lng, 
                        userLatLng.lat, userLatLng.lng
                    );
                    
                    // Convert to meters (result is in km)
                    const distanceInMeters = distance * 1000;
                    
                    if (distanceInMeters <= radius) {
                        usersWithinRadius.push({
                            ...user.toObject(),
                            distance: Math.round(distanceInMeters)
                        });
                    }
                }
            } catch (error) {
                console.error(`Error geocoding user location for user ${user._id}:`, error);
                // Continue with the next user
                continue;
            }
        }
        
        // Sort by distance (closest first)
        usersWithinRadius.sort((a, b) => a.distance - b.distance);
        
        res.status(200).json({ 
            users: usersWithinRadius,
            searchLocation: geocodeResponse.data.results[0].formatted_address,
            total: usersWithinRadius.length
        });
    } catch (error) {
        console.error('Error searching users by location:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Helper function to calculate distance between two points using the Haversine formula
function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371; // Radius of the Earth in km
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = 
        Math.sin(dLat/2) * Math.sin(dLat/2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) * 
        Math.sin(dLon/2) * Math.sin(dLon/2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    const distance = R * c; // Distance in km
    return distance;
}

// Middleware to verify user token
const verifyUserToken = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'Authorization token required' });
        }
        
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (!decoded.userId) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        
        // Check if user still exists in the database
        const user = await User.findById(decoded.userId);
        if (!user) {
            return res.status(401).json({ message: 'User account no longer exists' });
        }
        
        // Add user to request object
        req.user = user;
        next();
    } catch (error) {
        console.error('User auth error:', error);
        return res.status(401).json({ message: 'Authentication failed' });
    }
};

// Get messages for the authenticated user
app.get('/messages/user', verifyUserToken, async (req, res) => {
    try {
        // User is already available in req.user from the middleware
        const user = req.user;
        
        // Sort messages by date (newest first)
        const sortedMessages = user.messages.sort((a, b) => 
            new Date(b.sentAt).getTime() - new Date(a.sentAt).getTime()
        );
        
        res.status(200).json({ 
            success: true,
            data: sortedMessages
        });
    } catch (error) {
        console.error('Error retrieving messages:', error);
        res.status(500).json({ 
            success: false,
            message: 'Failed to retrieve messages', 
            error: error.message 
        });
    }
});

// Mark messages as read
app.post('/messages/read', verifyUserToken, async (req, res) => {
    try {
        const { messageIds } = req.body;
        
        if (!messageIds || !Array.isArray(messageIds) || messageIds.length === 0) {
            return res.status(400).json({ 
                success: false,
                message: 'Message IDs array is required' 
            });
        }
        
        // User is already available in req.user from the middleware
        const user = req.user;
        
        // Mark each message as read
        messageIds.forEach(messageId => {
            const message = user.messages.id(messageId);
            if (message) {
                message.read = true;
            }
        });
        
        // Save the updated user document
        await user.save();
        
        res.status(200).json({ 
            success: true,
            message: 'Messages marked as read successfully' 
        });
    } catch (error) {
        console.error('Error marking messages as read:', error);
        res.status(500).json({ 
            success: false,
            message: 'Failed to mark messages as read', 
            error: error.message 
        });
    }
});

app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});