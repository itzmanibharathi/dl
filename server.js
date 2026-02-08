const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/busbooking', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.log('MongoDB connection error:', err));

// =======================
// Models
// =======================

const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
}, { timestamps: true });

const BusSchema = new mongoose.Schema({
  busNumber: { type: String, required: true, unique: true },
  routeFrom: { type: String, required: true },
  routeTo: { type: String, required: true },
  farePerKm: { type: Number, required: true },
  stops: [{
    name: { type: String, required: true },
    kmFromStart: { type: Number, required: true }
  }],
  qrValue: { type: String, required: true, unique: true }
}, { timestamps: true });

const TicketSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  bus: { type: mongoose.Schema.Types.ObjectId, ref: 'Bus', required: true },
  busNumber: String,
  from: String,
  to: String,
  distance: Number,
  fare: Number,
  paymentId: { type: String, default: null },
  status: { type: String, enum: ['Pending', 'Paid', 'Verified'], default: 'Pending' },
  date: { type: Date, default: Date.now }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const Bus = mongoose.model('Bus', BusSchema);
const Ticket = mongoose.model('Ticket', TicketSchema);

// =======================
// Middleware
// =======================
const auth = async (req, res, next) => {
  const token = req.header('x-auth-token');
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey123');
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ msg: 'Admin access only' });
  }
  next();
};

// =======================
// Routes
// =======================

// Auth - Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ name, email, phone, password: hashedPassword });
    await user.save();

    const payload = { user: { id: user.id, role: user.role } };
    jwt.sign(payload, process.env.JWT_SECRET || 'secretkey123', { expiresIn: '7d' }, (err, token) => {
      if (err) throw err;
      res.json({ token });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Auth - Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const payload = { user: { id: user.id, role: user.role } };
    jwt.sign(payload, process.env.JWT_SECRET || 'secretkey123', { expiresIn: '7d' }, (err, token) => {
      if (err) throw err;
      res.json({
        token,
        user: { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role }
      });
    });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Get all buses (for search)
app.get('/api/bus', async (req, res) => {
  try {
    const buses = await Bus.find();
    res.json(buses);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Get bus by ID or QR
app.get('/api/bus/:id', async (req, res) => {
  try {
    let bus = await Bus.findById(req.params.id);
    if (!bus) {
      bus = await Bus.findOne({ qrValue: req.params.id });
    }
    if (!bus) return res.status(404).json({ msg: 'Bus not found' });
    res.json(bus);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Create ticket (user books)
app.post('/api/ticket', auth, async (req, res) => {
  const { busId, from, to, distance, fare } = req.body;

  try {
    const ticket = new Ticket({
      user: req.user.id,
      bus: busId,
      busNumber: req.body.busNumber,
      from,
      to,
      distance,
      fare,
      paymentId: null,
      status: 'Pending'
    });
    await ticket.save();
    res.json(ticket);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Get my tickets
app.get('/api/ticket/my', auth, async (req, res) => {
  try {
    const tickets = await Ticket.find({ user: req.user.id }).sort({ date: -1 });
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Admin verify ticket
app.post('/api/ticket/verify', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ msg: 'Admin only' });

  const { ticketIdOrPaymentId } = req.body;

  try {
    const ticket = await Ticket.findOne({
      $or: [
        { id: ticketIdOrPaymentId },
        { paymentId: ticketIdOrPaymentId }
      ]
    });

    if (!ticket) return res.status(404).json({ msg: 'Ticket not found' });

    ticket.status = 'Verified';
    await ticket.save();

    res.json({ msg: 'Ticket verified', ticket });
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

// Dummy payment update (in future replace with real Stripe webhook)
app.post('/api/ticket/pay/:id', auth, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ msg: 'Ticket not found' });
    if (ticket.user.toString() !== req.user.id) return res.status(403).json({ msg: 'Not your ticket' });

    ticket.paymentId = `PAY-${Math.floor(Math.random() * 1000000)}`;
    ticket.status = 'Paid';
    await ticket.save();

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ msg: 'Server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});