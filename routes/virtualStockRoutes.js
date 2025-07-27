const express = require("express");
const { NseIndia } = require("stock-nse-india");
const { Signup } = require("../models/Signup");
const stockRouter = express.Router();

const nseIndia = new NseIndia();

// Route to search for a stock by name/symbol
stockRouter.get("/search", async (req, res) => {
  try {
    const { query } = req.query;

    if (!query) {
      return res.status(400).json({ error: "Search query is required" });
    }

    const equitySymbols = await nseIndia.getAllStockSymbols();

    // Filter symbols based on the query (case insensitive)
    const filteredSymbols = equitySymbols.filter((symbol) =>
      symbol.toLowerCase().includes(query.toLowerCase())
    );

    // Limit results to top 10 matches
    const results = filteredSymbols.slice(0, 10);

    res.json({ results });
  } catch (error) {
    console.error("Error searching for stocks:", error);
    res.status(500).json({ error: "Failed to search for stocks" });
  }
});

// Route to get stock details and current price
stockRouter.get("/price", async (req, res) => {
  try {
    console.log("Aagaya baap");
    const { symbol } = req.query;

    if (!symbol) {
      return res.status(400).json({ error: "Stock symbol is required" });
    }

    // Get stock details from NSE
    const stockDetails = await nseIndia.getEquityDetails(symbol);
    console.log(stockDetails);

    // Get current market price
    const priceInfo = stockDetails.priceInfo.close;

    return res.json({
      symbol,
      name: stockDetails.info.companyName,
      price: priceInfo,
    });
  } catch (error) {
    console.error("Error fetching stock price:", error);
    res.status(500).json({ error: "Failed to fetch stock price" });
  }
});

// Route to buy stocks
stockRouter.post("/buy", async (req, res) => {
  try {
    const { email, symbol, quantity } = req.body;

    if (!email || !symbol || !quantity) {
      return res
        .status(400)
        .json({ error: "Email, symbol, and quantity are required" });
    }

    // Find the user
    const user = await Signup.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get current stock price
    const priceInfo = await nseIndia.getEquityDetails(symbol);
    const currentPrice = priceInfo.priceInfo.lastPrice;

    // Calculate total cost
    const totalCost = currentPrice * quantity;

    // Check if user has enough balance
    if (user.balance < totalCost) {
      return res.status(400).json({ error: "Insufficient balance" });
    }

    // Update user's balance
    user.balance -= totalCost;

    // Check if user already owns this stock
    const existingStockIndex = user.stocks.findIndex(
      (stock) => stock.symbol === symbol
    );

    if (existingStockIndex !== -1) {
      // Update existing stock
      const existingStock = user.stocks[existingStockIndex];
      const newQuantity = existingStock.quantity + parseInt(quantity);
      const newAvgPrice =
        (existingStock.boughtPrice * existingStock.quantity +
          currentPrice * parseInt(quantity)) /
        newQuantity;

      user.stocks[existingStockIndex].quantity = newQuantity;
      user.stocks[existingStockIndex].boughtPrice = newAvgPrice;
    } else {
      // Add new stock to portfolio
      user.stocks.push({
        symbol,
        boughtPrice: currentPrice,
        quantity: parseInt(quantity),
      });
    }

    // Update portfolio value
    let portfolioValue = 0;
    for (const stock of user.stocks) {
      try {
        const stockPrice = await nseIndia.getEquityDetails(stock.symbol);
        portfolioValue += stockPrice.priceInfo.lastPrice * stock.quantity;
      } catch (error) {
        console.error(`Error fetching price for ${stock.symbol}:`, error);
      }
    }
    user.pvalue = portfolioValue;

    // Save user
    await user.save();

    res.json({
      message: "Stock purchased successfully",
      transaction: {
        type: "buy",
        symbol,
        quantity: parseInt(quantity),
        price: currentPrice,
        total: totalCost,
      },
      newBalance: user.balance,
      portfolioValue: user.pvalue,
    });
  } catch (error) {
    console.error("Error buying stock:", error);
    res.status(500).json({ error: "Failed to buy stock" });
  }
});

// Route to sell stocks
stockRouter.post("/sell", async (req, res) => {
  try {
    const { email, symbol, quantity } = req.body;

    if (!email || !symbol || !quantity) {
      return res
        .status(400)
        .json({ error: "Email, symbol, and quantity are required" });
    }

    // Find the user
    const user = await Signup.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Check if user owns this stock
    const stockIndex = user.stocks.findIndex(
      (stock) => stock.symbol === symbol
    );

    if (stockIndex === -1) {
      return res.status(400).json({ error: "You do not own this stock" });
    }

    const stock = user.stocks[stockIndex];

    // Check if user has enough quantity to sell
    if (stock.quantity < quantity) {
      return res.status(400).json({ error: "Not enough shares to sell" });
    }

    // Get current stock price
    const priceInfo = await nseIndia.getEquityDetails(symbol);
    const currentPrice = priceInfo.priceInfo.lastPrice;

    // Calculate total sale amount
    const totalSale = currentPrice * quantity;

    // Update user's balance
    user.balance += totalSale;

    // Update stock quantity or remove if selling all
    if (stock.quantity === parseInt(quantity)) {
      // Remove stock from portfolio
      user.stocks.splice(stockIndex, 1);
    } else {
      // Update quantity
      user.stocks[stockIndex].quantity -= parseInt(quantity);
    }

    // Update portfolio value
    let portfolioValue = 0;
    for (const stock of user.stocks) {
      try {
        const stockPrice = await nseIndia.getEquityDetails(stock.symbol);
        portfolioValue += stockPrice.priceInfo.lastPrice * stock.quantity;
      } catch (error) {
        console.error(`Error fetching price for ${stock.symbol}:`, error);
      }
    }
    user.pvalue = portfolioValue;

    // Save user
    await user.save();

    res.json({
      message: "Stock sold successfully",
      transaction: {
        type: "sell",
        symbol,
        quantity: parseInt(quantity),
        price: currentPrice,
        total: totalSale,
      },
      newBalance: user.balance,
      portfolioValue: user.pvalue,
    });
  } catch (error) {
    console.error("Error selling stock:", error);
    res.status(500).json({ error: "Failed to sell stock" });
  }
});

// Route to get user portfolio
stockRouter.get("/portfolio", async (req, res) => {
  try {
    const { email } = req.query;

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    // Find the user
    const user = await Signup.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Get current prices for all stocks in portfolio
    const portfolio = [];
    let totalValue = 0;
    let totalInvestment = 0;
    let totalProfitLoss = 0;
    let profitableStocks = 0;
    let lossStocks = 0;

    for (const stock of user.stocks) {
      try {
        const priceInfo = await nseIndia.getEquityDetails(stock.symbol);
        const currentPrice = priceInfo.priceInfo.lastPrice;
        const stockValue = currentPrice * stock.quantity;
        const investmentValue = stock.boughtPrice * stock.quantity;
        const profitLoss = (currentPrice - stock.boughtPrice) * stock.quantity;
        const profitLossPercentage =
          ((currentPrice - stock.boughtPrice) / stock.boughtPrice) * 100;

        portfolio.push({
          symbol: stock.symbol,
          quantity: stock.quantity,
          boughtPrice: stock.boughtPrice,
          currentPrice,
          value: stockValue,
          profitLoss,
          profitLossPercentage,
        });

        // Track profitable vs loss-making stocks
        if (profitLoss > 0) {
          profitableStocks++;
        } else if (profitLoss < 0) {
          lossStocks++;
        }

        totalValue += stockValue;
        totalInvestment += investmentValue;
        totalProfitLoss += profitLoss;
      } catch (error) {
        console.error(`Error fetching price for ${stock.symbol}:`, error);

        portfolio.push({
          symbol: stock.symbol,
          quantity: stock.quantity,
          boughtPrice: stock.boughtPrice,
          error: "Failed to fetch current price",
        });
      }
    }

    // Calculate overall portfolio performance
    const overallProfitLossPercentage =
      totalInvestment > 0 ? (totalProfitLoss / totalInvestment) * 100 : 0;

    // Generate insights
    // Filter out stocks with errors for performance analysis
    const validStocks = portfolio.filter((stock) => !stock.error);

    // Only calculate best performer if we have valid stocks
    let bestPerformer = null;
    if (validStocks.length > 0) {
      bestPerformer = validStocks.reduce(
        (best, current) =>
          current.profitLossPercentage > best.profitLossPercentage
            ? current
            : best,
        validStocks[0]
      );

      // Only keep best performer if it's actually in profit
      if (bestPerformer.profitLossPercentage <= 0) {
        bestPerformer = null;
      }
    }

    // Only calculate worst performer if we have valid stocks
    let worstPerformer = null;
    if (validStocks.length > 0) {
      // Only consider stocks that are in loss or underperforming
      const underperformingStocks = validStocks.filter(
        (stock) =>
          stock.profitLossPercentage < 0 ||
          (validStocks.length > 1 &&
            stock.profitLossPercentage <
              validStocks.reduce((sum, s) => sum + s.profitLossPercentage, 0) /
                validStocks.length)
      );

      if (underperformingStocks.length > 0) {
        worstPerformer = underperformingStocks.reduce(
          (worst, current) =>
            current.profitLossPercentage < worst.profitLossPercentage
              ? current
              : worst,
          underperformingStocks[0]
        );
      }
    }

    const insights = {
      overallStatus:
        totalProfitLoss > 0
          ? "Profit"
          : totalProfitLoss < 0
          ? "Loss"
          : "Neutral",
      totalProfitLoss,
      overallProfitLossPercentage,
      profitableStocks,
      lossStocks,
      bestPerformer,
      worstPerformer,
    };

    // Update portfolio value in database
    user.pvalue = totalValue;
    await user.save();

    res.json({
      balance: user.balance,
      portfolio,
      totalValue,
      totalInvestment,
      insights,
    });
  } catch (error) {
    console.error("Error fetching portfolio:", error);
    res.status(500).json({ error: "Failed to fetch portfolio" });
  }
});

module.exports = stockRouter;
