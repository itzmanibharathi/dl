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
mongoose
  .connect(process.env.MONGO_URI || 'mongodb://localhost:27017/busbooking')
  .then(() => console.log('MongoDB Connected'))
  .catch((err) => console.error('MongoDB connection error:', err));

// ──────────────────────────────────────── MODELS ────────────────────────────────────────
const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
  },
  { timestamps: true }
);

const BusSchema = new mongoose.Schema(
  {
    busNumber: { type: String, required: true, unique: true },
    routeFrom: { type: String, required: true },
    routeTo: { type: String, required: true },
    stops: [
      {
        name: { type: String, required: true },
        kmFromStart: { type: Number, required: true, min: 0 },
      },
    ],
    fares: { type: Map, of: Number, default: {} }, // ← New: per-stop-pair fares
    qrValue: { type: String, required: true, unique: true },
  },
  { timestamps: true }
);

const TicketSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    bus: { type: mongoose.Schema.Types.ObjectId, ref: 'Bus', required: true },
    busNumber: { type: String, required: true },
    from: { type: String, required: true },
    to: { type: String, required: true },
    distance: { type: Number, required: true, min: 0 },
    quantity: { type: Number, default: 1, min: 1 },
    fare: { type: Number, required: true, min: 0 },
    paymentId: { type: String, default: null },
    status: {
      type: String,
      enum: ['Pending', 'Paid', 'Verified'],
      default: 'Pending',
    },
    date: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const User = mongoose.model('User', UserSchema);
const Bus = mongoose.model('Bus', BusSchema);
const Ticket = mongoose.model('Ticket', TicketSchema);

// ──────────────────────────────────────── MIDDLEWARE ────────────────────────────────────────
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

// ──────────────────────────────────────── ROUTES ────────────────────────────────────────

// Auth - Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, password, role = 'user' } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ msg: 'User already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ name, email, phone, password: hashedPassword, role });
    await user.save();

    const payload = { user: { id: user.id, role: user.role } };
    jwt.sign(
      payload,
      process.env.JWT_SECRET || 'secretkey123',
      { expiresIn: '7d' },
      (err, token) => {
        if (err) throw err;
        res.json({
          token,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role,
          },
        });
      }
    );
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
    jwt.sign(
      payload,
      process.env.JWT_SECRET || 'secretkey123',
      { expiresIn: '7d' },
      (err, token) => {
        if (err) throw err;
        res.json({
          token,
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
            phone: user.phone,
            role: user.role,
          },
        });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Add bus (admin only) — FIXED VERSION
app.post('/api/bus', auth, isAdmin, async (req, res) => {
  const { busNumber, routeFrom, routeTo, stops, fares, qrValue } = req.body;

  try {
    // Required fields — removed farePerKm
    if (!busNumber || !routeFrom || !routeTo || !stops || !Array.isArray(stops) || stops.length < 2) {
      return res.status(400).json({
        msg: 'Required fields: busNumber, routeFrom, routeTo, and at least 2 stops'
      });
    }

    // Auto-generate qrValue if missing
    const finalQrValue = qrValue || `QR-${busNumber.trim().replace(/\s+/g, '-')}-${Date.now()}`;

    // Check duplicates
    let bus = await Bus.findOne({ busNumber });
    if (bus) return res.status(400).json({ msg: 'Bus number already exists' });

    bus = await Bus.findOne({ qrValue: finalQrValue });
    if (bus) return res.status(400).json({ msg: 'QR value already exists' });

    // Create new bus
    bus = new Bus({
      busNumber,
      routeFrom,
      routeTo,
      stops,
      fares: fares || {}, // per-pair fares
      qrValue: finalQrValue,
    });

    await bus.save();

    res.status(201).json({
      msg: 'Bus added successfully',
      bus,
    });
  } catch (err) {
    console.error('Add bus error:', err);
    res.status(500).json({ msg: 'Server error while adding bus' });
  }
});

// Get all buses (public)
app.get('/api/bus', async (req, res) => {
  try {
    const buses = await Bus.find().sort({ createdAt: -1 });
    res.json(buses);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Get bus by ID or qrValue
app.get('/api/bus/:id', async (req, res) => {
  try {
    let bus = await Bus.findById(req.params.id);
    if (!bus) {
      bus = await Bus.findOne({ qrValue: req.params.id });
    }
    if (!bus) return res.status(404).json({ msg: 'Bus not found' });
    res.json(bus);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Create ticket
app.post('/api/ticket', auth, async (req, res) => {
  const { busId, busNumber, from, to, distance, quantity = 1 } = req.body;

  try {
    const bus = await Bus.findById(busId);
    if (!bus) return res.status(404).json({ msg: 'Bus not found' });

    const startStop = bus.stops.find((s) => s.name === from);
    const endStop = bus.stops.find((s) => s.name === to);

    if (!startStop || !endStop || startStop.kmFromStart >= endStop.kmFromStart) {
      return res.status(400).json({ msg: 'Invalid from/to stops' });
    }

    const calcDistance = endStop.kmFromStart - startStop.kmFromStart;

    // Use pre-defined fare if available, else fallback
    const fareKey = `${from}-${to}`;
    const farePerUnit = bus.fares.get(fareKey) || 1; // fallback to 1 if no fare defined
    const fare = calcDistance * farePerUnit * quantity;

    const ticket = new Ticket({
      user: req.user.id,
      bus: busId,
      busNumber,
      from,
      to,
      distance: calcDistance,
      quantity,
      fare,
    });

    await ticket.save();
    res.json(ticket);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Get my tickets
app.get('/api/ticket/my', auth, async (req, res) => {
  try {
    const tickets = await Ticket.find({ user: req.user.id }).sort({ date: -1 });
    res.json(tickets);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Pay ticket (dummy)
app.post('/api/ticket/pay/:id', auth, async (req, res) => {
  try {
    const ticket = await Ticket.findById(req.params.id);
    if (!ticket) return res.status(404).json({ msg: 'Ticket not found' });
    if (ticket.user.toString() !== req.user.id) {
      return res.status(403).json({ msg: 'Not your ticket' });
    }
    if (ticket.status !== 'Pending') {
      return res.status(400).json({ msg: 'Ticket already processed' });
    }

    ticket.paymentId = `PAY-${Math.random().toString(36).substring(7).toUpperCase()}`;
    ticket.status = 'Paid';
    await ticket.save();

    res.json(ticket);
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Verify ticket (admin only)
app.post('/api/ticket/verify', auth, isAdmin, async (req, res) => {
  const { identifier } = req.body;

  try {
    const ticket = await Ticket.findOne({
      $or: [
        { _id: identifier },
        { paymentId: identifier },
      ],
    }).populate('bus');

    if (!ticket) return res.status(404).json({ msg: 'Ticket not found' });

    ticket.status = 'Verified';
    await ticket.save();

    res.json({
      msg: 'Ticket verified successfully',
      ticket: {
        id: ticket._id,
        busNumber: ticket.busNumber,
        from: ticket.from,
        to: ticket.to,
        fare: ticket.fare,
        status: ticket.status,
        date: ticket.date,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: 'Server error' });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
