const express = require("express");
const axios = require("axios");
const recommendationRoutes = express.Router();
const Groq = require("groq-sdk");
const { csvFile } = require("../models/CsvFile");
require('dotenv').config();

let mutualFundsData = {};
async function fetchAllMFCSVData() {
  const fileMappings = {
    mutualFunds: "mutual_funds_data - Main.csv",
  };

  for (const [key, fileName] of Object.entries(fileMappings)) {
    try {
      const csvDocument = await csvFile.findOne({ fileName });
      if (csvDocument && csvDocument.data) {
        mutualFundsData[key] = csvDocument.data;
        console.log(`${fileName} data loaded successfully!`);
      } else {
        console.error(`CSV file ${fileName} not found or has no data.`);
      }
    } catch (error) {
      console.error(`Error loading ${fileName}:`, error.message);
    }
  }
}

async function recommendMutualFunds(userInput) {
  await fetchAllMFCSVData();

  const { user_age, user_risk_appetite } = userInput;

  let allFunds = Object.values(mutualFundsData).flat();
  if (!allFunds || allFunds.length === 0) {
    throw new Error("No mutual funds data available.");
  }

  let filteredData = allFunds.filter(
    (fund) => fund["Risk"] === user_risk_appetite
  );

  if (filteredData.length === 0) {
    throw new Error("No funds match the given risk appetite.");
  }

  filteredData = filteredData.sort((a, b) => {
    return (
      b["Sharpe"] - a["Sharpe"] ||
      b["Alpha"] - a["Alpha"] ||
      a["Beta"] - b["Beta"] ||
      a["Expense ratio"] - b["Expense ratio"] ||
      a["Standard Deviation"] - b["Standard Deviation"]
    );
  });

  let recommendedFunds;
  if (18 <= user_age && user_age < 30) {
    const highRiskFunds = filteredData
      .filter((fund) => fund["Risk"] === "High")
      .slice(0, 2);
    const otherFunds = filteredData
      .filter((fund) => !highRiskFunds.includes(fund))
      .slice(0, 1);
    recommendedFunds = [...highRiskFunds, ...otherFunds];
  } else if (30 <= user_age && user_age <= 50) {
    const highRiskFunds = filteredData
      .filter((fund) => fund["Risk"] === "High")
      .slice(0, 1);
    const otherFunds = filteredData
      .filter((fund) => !highRiskFunds.includes(fund))
      .slice(0, 2);
    recommendedFunds = [...highRiskFunds, ...otherFunds];
  } else {
    recommendedFunds = filteredData
      .filter((fund) => fund["Risk"] !== "High")
      .slice(0, 3);
  }

  return recommendedFunds;
}

async function getRecommendationFromGroq(userInput, recommendations) {
  const {
    user_age,
    user_risk_appetite,
    user_income,
    user_savings,
    user_investment_amount,
  } = userInput;

  const prompt = `
    I want to invest in mutual funds. I am ${user_age} years old. I have a ${user_risk_appetite} risk appetite.
    I earn ${user_income} INR per month. I save ${user_savings} INR per month. From the savings amount, I want to
    invest ${user_investment_amount} INR per month. Analyze these mutual funds and suggest only one mutual fund.
    Give me reasons behind your suggestion.

    ${JSON.stringify(recommendations, null, 2)}`;

  try {
    const chatCompletion = await groq.chat.completions.create({
      messages: [{ role: "user", content: prompt }],
      model: "llama3-8b-8192",
    });

    return (
      chatCompletion.choices[0]?.message?.content || "No response received."
    );
  } catch (error) {
    console.error("Error communicating with Groq API:", error.message);
    return "Unable to get a recommendation at this time.";
  }
}

recommendationRoutes.post("/mutualFunds", async (req, res) => {
  const userInput = req.body;

  if (!userInput) {
    return res
      .status(400)
      .json({ error: "Invalid input: User data is required" });
  }

  try {
    const recommendations = await recommendMutualFunds(userInput); // Added await
    const groqResponse = await getRecommendationFromGroq(
      userInput,
      recommendations
    );

    res.json({
      recommendations,
      groqRecommendation: groqResponse,
    });
  } catch (error) {
    console.error("Error in recommendation route:", error.message);
    res.status(500).json({ error: error.message });
  }
});

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY_AASHISH });

let datasets = {
  taxSavingFd: [],
  seniorPublicFd: [],
  seniorPrivateFd: [],
  comparisonPublicFd: [],
  comparisonPrivateFd: [],
};

function calculateMaturity(principal, rate, termYears) {
  return principal * Math.pow(1 + rate / 100, termYears);
}

async function fetchAllCSVData() {
  const fileMappings = {
    taxSavingFd: "tax_fd.csv",
    seniorPublicFd: "senior_public.csv",
    seniorPrivateFd: "senior_private.csv",
    comparisonPublicFd: "public_sector_banks.csv",
    comparisonPrivateFd: "private_sector_banks.csv",
  };

  for (const [key, fileName] of Object.entries(fileMappings)) {
    const csvDocument = await csvFile.findOne({ fileName });
    if (csvDocument) {
      datasets[key] = csvDocument.data;
    } else {
      console.warn(`CSV file "${fileName}" not found in the database.`);
    }
  }
}

async function loadAndCleanData() {
  await fetchAllCSVData();
  Object.entries(datasets).forEach(([key, data]) => {
    data.forEach((row) => {
      if (key === "taxSavingFd") {
        row["General Citizens"] = row["General Citizens"]
          ? parseFloat(row["General Citizens"].replace(/[^0-9.]/g, "")) || 0
          : undefined;

        row["Senior Citizens"] = row["Senior Citizens"]
          ? parseFloat(row["Senior Citizens"].replace(/[^0-9.]/g, "")) || 0
          : undefined;
      } else {
        Object.keys(row).forEach((col) => {
          if (col === "3-years tenure") {
            row["3-year tenure"] = row[col];
            delete row[col];
          }
          if (col === "5-years tenure") {
            row["5-year tenure"] = row[col];
            delete row[col];
          }
        });

        [
          "Highest slab",
          "1-year tenure",
          "3-year tenure",
          "5-year tenure",
        ].forEach((col) => {
          if (row[col]) {
            row[col] = parseFloat(row[col].replace(/[^0-9.]/g, ""));
          }
        });
      }
    });

    if (key === "seniorPublicFd" || key === "seniorPrivateFd") {
      datasets[key].forEach((row) => {
        delete row["General Citizens"];
        delete row["Senior Citizens"];
      });
    }
  });

  // console.log("Data cleaned and processed:", datasets);
}

loadAndCleanData();

function recommendFds(age, amount, termYears) {
  const taxSavingFd = datasets.taxSavingFd;
  const seniorPublicFd = datasets.seniorPublicFd;
  const seniorPrivateFd = datasets.seniorPrivateFd;
  const comparisonPublicFd = datasets.comparisonPublicFd;
  const comparisonPrivateFd = datasets.comparisonPrivateFd;

  let recommendations = [];

  if (age > 60 && amount <= 150000) {
    taxSavingFd.forEach((fd) => {
      const maturityAmount = calculateMaturity(
        amount,
        fd["Senior Citizens"],
        termYears
      );
      fd["Maturity Amount"] = maturityAmount;
    });

    recommendations = taxSavingFd
      .sort((a, b) => b["Maturity Amount"] - a["Maturity Amount"])
      .slice(0, 3);

    return recommendations.map((fd) => {
      return {
        bank: fd["Banks"],
        interestRate: parseFloat(fd["Senior Citizens"].toFixed(2)),
        maturityAmount: parseFloat(fd["Maturity Amount"].toFixed(2)),
        reason: "Tax Saving FD for Senior Citizens",
      };
    });
  } else if (age <= 60 && amount <= 150000) {
    taxSavingFd.forEach((fd) => {
      const maturityAmount = calculateMaturity(
        amount,
        fd["General Citizens"],
        termYears
      );
      fd["Maturity Amount"] = maturityAmount;
    });

    recommendations = taxSavingFd
      .sort((a, b) => b["Maturity Amount"] - a["Maturity Amount"])
      .slice(0, 3);

    return recommendations.map((fd) => {
      return {
        bank: fd["Banks"],
        interestRate: parseFloat(fd["General Citizens"].toFixed(2)),
        maturityAmount: parseFloat(fd["Maturity Amount"].toFixed(2)),
        reason: "Tax Saving FD for General Citizens",
      };
    });
  } else if (age > 60 && amount > 150000) {
    const seniorFd = seniorPublicFd.concat(seniorPrivateFd);
    seniorFd.forEach((fd) => {
      const averageRate =
        (fd["1-year tenure"] + fd["3-year tenure"] + fd["5-year tenure"]) / 3;
      const maturityAmount = calculateMaturity(amount, averageRate, termYears);
      fd["Average Rate (%)"] = averageRate;
      fd["Maturity Amount"] = maturityAmount;
    });

    recommendations = seniorFd
      .sort((a, b) => b["Maturity Amount"] - a["Maturity Amount"])
      .slice(0, 3);

    return recommendations.map((fd) => {
      return {
        bank: fd["Bank Name"],
        interestRate: parseFloat(fd["Average Rate (%)"].toFixed(2)),
        maturityAmount: parseFloat(fd["Maturity Amount"].toFixed(2)),
        reason: "Senior Citizen FD (Public & Private Banks)",
      };
    });
  } else if (age <= 60 && amount > 150000) {
    const comparisonFd = comparisonPublicFd.concat(comparisonPrivateFd);
    comparisonFd.forEach((fd) => {
      const averageRate =
        (fd["1-year tenure"] + fd["3-year tenure"] + fd["5-year tenure"]) / 3;
      const maturityAmount = calculateMaturity(amount, averageRate, termYears);
      fd["Average Rate (%)"] = averageRate;
      fd["Maturity Amount"] = maturityAmount;
    });

    recommendations = comparisonFd
      .sort((a, b) => b["Maturity Amount"] - a["Maturity Amount"])
      .slice(0, 3);

    return recommendations.map((fd) => {
      return {
        bank: fd["Public Sector Banks"] || fd["Private Sector Banks"],
        interestRate: parseFloat(fd["Average Rate (%)"].toFixed(2)),
        maturityAmount: parseFloat(fd["Maturity Amount"].toFixed(2)),
        reason: "Comparison FD (Public & Private Banks)",
      };
    });
  } else {
    console.log("No recommendations available for the given inputs.");
    return [];
  }
}

recommendationRoutes.post("/fd", async (req, res) => {
  console.log("Received request for FD recommendation");
  const userInput = req.body;
  const { age, amount, termYears } = userInput;

  if (!age || !amount || !termYears) {
    return res.status(400).json({
      error: "Invalid input: Age, amount, and termYears are required",
    });
  }

  try {
    const recommendationDetails = recommendFds(age, amount, termYears);
    const bestRecommendation = recommendationDetails[0];
    const prompt = `
      I am ${age} years old and want to invest ${amount} INR for ${termYears} years.
      Based on the following FD option, suggest the best one and explain why it is the best choice given my age, amount, and tenure:
      FD Option:
      - Bank Name: ${bestRecommendation.bank}
      - Interest Rate: ${bestRecommendation.interestRate}%
      - Maturity Amount: INR ${bestRecommendation.maturityAmount}
      - Reason: ${bestRecommendation.reason}
      Please explain why this is the best choice in 500 to 600 characters, starting with the bank name, maturity amount, and reasons for selection.`;
    const response = await groq.chat.completions.create({
      messages: [{ role: "user", content: prompt }],
      model: "llama3-8b-8192",
    });

    let groqRecommendation =
      response.choices[0]?.message?.content || "No response received.";
    groqRecommendation = groqRecommendation.slice(0, 600);
    res.json({
      bestRecommendation: {
        bank: bestRecommendation.bank,
        interestRate: bestRecommendation.interestRate,
        maturityAmount: bestRecommendation.maturityAmount,
        reason: bestRecommendation.reason,
      },
      groqRecommendation,
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const postStockRecommendation = async (question) => {
  const url = "https://wealthwise-agent.onrender.com/stockRecommandation";
  try {
    const response = await axios.post(url, question);
    return response.data;
  } catch (firstError) {
    console.warn("First attempt failed, retrying...");
    try {
      const retryResponse = await axios.post(url, question);
      return retryResponse.data;
    } catch (secondError) {
      console.error("Both attempts failed:", secondError);
      throw new Error("Error fetching stock recommendation after retrying.");
    }
  }
};

recommendationRoutes.post("/stocks", async (req, res) => {
  const { formData } = req.body;
  console.log("formData", formData);
  try {
    const answer = await postStockRecommendation(formData);
    res.status(200).json({ answer });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

module.exports = recommendationRoutes;
