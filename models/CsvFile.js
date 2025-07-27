let mongoose = require("mongoose");

const csvfile = new mongoose.Schema(
  {
    fileName: { type: String, required: true },
    data: { type: Array, required: true },
  },
  { timestamps: true }
);

const csvFile = mongoose.model("Data", csvfile);

module.exports = { csvFile };
