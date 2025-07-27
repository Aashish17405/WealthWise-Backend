const express = require("express");
const axios = require("axios");
const { Signup } = require("../models/Signup");
const cron = require("node-cron");
const cheerio = require("cheerio");
const appRoutes = express.Router();

require('dotenv').config();

cron.schedule("0 0 1 * *", async () => {
  try {
    console.log("Resetting count for all users...");
    await Signup.updateMany({}, { count: 0 });
    console.log("Count reset successfully for all users.");
  } catch (error) {
    console.error("Error resetting count:", error.message);
  }
});

appRoutes.get("/nifty50", async (req, res) => {
  try {
    const { data: html } = await axios.get(
      "https://www.moneyworks4me.com/best-index/nse-stocks/top-nifty-50-companies-list/"
    );
    const $ = cheerio.load(html);

    const top50 = [];

    $("tr.table-content").each((_, row) => {
      const cols = $(row).find("td");

      const companyName = $(cols[1]).find("a").text().trim();
      const lastPrice = parseFloat($(cols[2]).text().replace(/,/g, ""));
      const percentChangeText = $(cols[3]).text().trim();
      const percentChange = percentChangeText
        ? parseFloat(percentChangeText.replace("%", ""))
        : undefined;

      const highText = $(cols[5]).text().split("\n")[0].trim();
      const lowText = $(cols[6]).text().split("\n")[0].trim();

      const symbol = companyName?.split(" ")[0].toUpperCase();

      const stock = {
        symbol,
        lastPrice: isNaN(lastPrice) ? undefined : lastPrice,
        percentChange: isNaN(percentChange) ? undefined : percentChange,
        high: isNaN(parseFloat(highText)) ? undefined : parseFloat(highText),
        low: isNaN(parseFloat(lowText)) ? undefined : parseFloat(lowText),
      };

      top50.push(
        Object.fromEntries(
          Object.entries(stock).filter(([_, v]) => v !== undefined)
        )
      );
    });

    res.json(top50);
  } catch (error) {
    console.error("Error scraping Nifty 50 data:", error.message);
    res.status(500).json({ error: "Failed to fetch Nifty 50 data" });
  }
});

module.exports = appRoutes;