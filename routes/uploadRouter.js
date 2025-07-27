const express = require("express");
const multer = require("multer");
const csvtojson = require("csvtojson");
const { Readable } = require("stream");
const { csvFile } = require("../models/CsvFile");

const upload = multer({ storage: multer.memoryStorage() });
const uploadRouter = express.Router();

uploadRouter.post("/", upload.single("file"), async (req, res) => {
  try {
    console.log("Received file:", req.file);
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    if (!req.file?.buffer) {
      return res
        .status(400)
        .json({ message: "Uploaded file is empty or invalid" });
    }

    const fileName = req.file.originalname;
    let jsonArray;

    try {
      const readableFile = new Readable();
      readableFile.push(req.file.buffer);
      readableFile.push(null);
      jsonArray = await csvtojson().fromStream(readableFile);
    } catch (csvError) {
      return res.status(500).json({
        message: "Error processing CSV file",
        error: csvError.message,
      });
    }
    const existingDocument = await csvFile.findOne({ fileName });
    if (existingDocument) {
      existingDocument.data = jsonArray;
      await existingDocument.save();
    } else {
      await csvFile.create({ fileName, data: jsonArray });
    }
    res
      .status(200)
      .json({ message: `Data from ${fileName} successfully processed` });
  } catch (error) {
    console.error("Error during file upload:", error);
    res
      .status(500)
      .json({ message: "Failed to process file", error: error.message });
  }
});

module.exports = uploadRouter;
