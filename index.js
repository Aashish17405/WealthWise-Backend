const express = require("express");
const app = express();
const stockRouter = require("./routes/virtualStockRoutes");
const personalisedStockRoutes = require("./routes/recommendationRoutes");
const expenseTrackerRoutes = require("./routes/expenseTrackerRoutes");
const ragRouter = require("./routes/ragRouter");
const uploadRouter = require("./routes/uploadRouter");
const authRouter = require("./routes/authRoutes");
const userRouter = require("./routes/userRoutes");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
dotenv.config();
app.use(express.json());
const jwt = require("jsonwebtoken");
const CryptoJS = require("crypto-js");
const appRoutes = require("./routes/appRoutes");

const corsOptions = {
  origin: [
    "https://wealthwisee.vercel.app",
    "https://wealthwisee.live",
    "https://www.wealthwisee.live",
  ],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
};

// app.use(cors(corsOptions));

app.use(cors({
    origin: ["http://localhost:3000", "http://localhost:3001", "http://localhost:5173"], // Allow both common dev ports
    credentials: true, // Needed if you're using cookies
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
  }));
// const validateOrigin = (req, res, next) => {
//     const allowedOrigins = ['https://wealthwisee.vercel.app','https://wealthwisee.live','https://www.wealthwisee.live'];
//     if (!allowedOrigins.includes(req.headers.origin)) {
//         return res.status(403).json({ error: 'Unauthorized request' });
//     }
//     next();
// };

// const authenticateToken = (req, res, next) => {
//     if (req.path === '/api/login' || req.path === '/api/findmail' || req.path === '/api/signup' || req.path === '/api/nifty' || req.path ==='/api/stock' || req.path ==='/api/portfolio' ) {
//         return next();
//     }
//     const authHeader = req.headers['authorization'];
//     const token = authHeader && authHeader.split(' ')[1];
//     if (!token) return res.status(401).send('Token required');

//     jwt.verify(token,process.env.TOKEN, (err, user) => {
//         if (err) return res.status(403).send('Invalid token');
//         req.user = user;
//         next();
//     });
// };

// app.use(validateOrigin);
// app.use(authenticateToken);

const db = async () => {
  try {
    await mongoose.connect(process.env.DBURI);
  } catch (err) {
    console.log("Error connecting to database");
  }
};
db();

app.use("/api", appRoutes);
app.use("/api/stock", stockRouter);
app.use("/api/recommendations", personalisedStockRoutes);
app.use("/api/rag", ragRouter);
app.use("/api/expense", expenseTrackerRoutes);
app.use("/api/upload", uploadRouter);
app.use("/api/auth", authRouter);
app.use("/api/user", userRouter); 

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

app.listen(5000, () => {
  console.log("Backend server listening at port 5000");
});
