let mongoose = require("mongoose");

const StockSchema = new mongoose.Schema({
  symbol: { type: String, required: true },
  boughtPrice: { type: Number, required: true },
  quantity: { type: Number, required: true },
});

const signup = new mongoose.Schema(
  {
    name: { type: String },
    phone: { type: String },
    email: { type: String, unique: true, required: true },
    password: { type: String },
    profile: { type: String },
    count: { type: Number, default: 0 },
    balance: { type: Number, default: 3000 },
    pvalue: { type: Number, default: 0 },
    stocks: [StockSchema],
  },
  {
    timestamps: true,
  }
);

const Signup = mongoose.model("signup", signup);

module.exports = { Signup };
