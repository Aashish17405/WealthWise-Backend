const express = require("express");
const expenseTrackerRouter = express.Router();
const { ChatGroq } = require("@langchain/groq");
const { PromptTemplate } = require("@langchain/core/prompts");
const { StringOutputParser } = require("@langchain/core/output_parsers");
const { get_retrieverExpense } = require("../utils/utils");
const { UserData } = require("../models/UserData");

let retriever2 = null;

async function initializeRetrievers() {
  try {
    retriever2 = await get_retrieverExpense();
    console.log("Retrievers initialized successfully");
  } catch (error) {
    console.error("Failed to initialize retrievers:", error);
    throw error;
  }
}

initializeRetrievers().catch(console.error);

expenseTrackerRouter.post("/submitdata", async (req, res) => {
  console.log("Received data:", req.body);
  const formData = req.body.formData;

  if (!formData) {
    return res.status(400).json({ error: "No form data provided" });
  }

  try {
    const { email, income, age, city } = formData;
    if (!email || !income || !age || !city) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const now = new Date();
    const month = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(
      2,
      "0"
    )}`;
    const existingData = await UserData.findOne({
      email,
      month,
    });

    if (existingData) {
      Object.assign(existingData, {
        income: formData.income || existingData.income,
        age: formData.age || existingData.age,
        city: formData.city || existingData.city,
        foodAtHome: formData.foodAtHome || existingData.foodAtHome,
        foodAwayFromHome:
          formData.foodAwayFromHome || existingData.foodAwayFromHome,
        housing: formData.housing || existingData.housing,
        transportation: formData.transportation || existingData.transportation,
        healthcare: formData.healthcare || existingData.healthcare,
        education: formData.education || existingData.education,
        entertainment: formData.entertainment || existingData.entertainment,
        personalCare: formData.personalCare || existingData.personalCare,
        apparelAndServices:
          formData.apparelAndServices || existingData.apparelAndServices,
        tobaccoProducts:
          formData.tobaccoProducts || existingData.tobaccoProducts,
        personalfinance:
          formData.personalfinance || existingData.personalfinance,
        alcoholicBeverages:
          formData.alcoholicBeverages || existingData.alcoholicBeverages,
        savings: formData.savings || existingData.savings,
        others: formData.others || existingData.others,
      });

      await existingData.save();
      return res
        .status(200)
        .json({ message: "Data updated successfully", data: existingData });
    } else {
      // Create new data
      const now = new Date();
      const month = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(
        2,
        "0"
      )}`;
      const newData = new UserData({
        email: formData.email || "",
        income: formData.income || "",
        age: formData.age || "",
        city: formData.city || "",
        foodAtHome: formData.foodAtHome || "",
        foodAwayFromHome: formData.foodAwayFromHome || "",
        housing: formData.housing || "",
        transportation: formData.transportation || "",
        healthcare: formData.healthcare || "",
        education: formData.education || "",
        entertainment: formData.entertainment || "",
        personalCare: formData.personalCare || "",
        apparelAndServices: formData.apparelAndServices || "",
        tobaccoProducts: formData.tobaccoProducts || "",
        personalfinance: formData.personalfinance || "",
        alcoholicBeverages: formData.alcoholicBeverages || "",
        savings: formData.savings || "",
        others: formData.others || "",
        date: new Date(),
        month: month,
      });

      await newData.save();
      return res
        .status(201)
        .json({ message: "Data saved successfully", data: newData });
    }
  } catch (error) {
    console.error("Error saving or updating data:", error.message);
    return res
      .status(500)
      .json({ error: "Internal server error", details: error.message });
  }
});

expenseTrackerRouter.post("/getAnalysis", async (req, res) => {
  if (!retriever2) {
    return res.status(503).json({
      message:
        "Service initializing, please try again in a moment. Retriever not ready.",
    });
  }
  const { salary, age, cityType, userExpenses, data } = req.body;

  if (
    !salary ||
    !age ||
    !cityType ||
    !userExpenses ||
    !data ||
    Object.keys(userExpenses).length === 0
  ) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  try {
    class BudgetReportGenerator {
      static BENCHMARK_EXPENSES = {
        foodAtHome: 9.8,
        foodAwayFromHome: 5.9,
        alcoholicBeverages: 0.6,
        housing: 24,
        apparelAndServices: 2,
        transportation: 12,
        healthCare: 6,
        entertainment: 3.5,
        personalCare: 1,
        education: 2,
        tobacco: 0.5,
        other: 1.5,
        personalFinanceAndPensions: 10,
        savings: 22,
      };
      static CITY_MULTIPLIERS = {
        metro: 1.3,
        tier1: 1.15,
        tier2: 1,
        tier3: 0.85,
        rural: 0.7,
      };
      static AGE_MULTIPLIERS = {
        "18-25": 0.9,
        "26-35": 1.1,
        "36-45": 1.2,
        "46-55": 1.0,
        "56-65": 0.8,
        "65+": 0.7,
      };
      constructor(salary, age, cityType) {
        this.salary = parseFloat(salary);
        this.age = parseInt(age);
        this.cityType = (cityType && cityType.toLowerCase()) || "tier2";
      }
      _getAgeGroup() {
        if (this.age >= 18 && this.age <= 25) return "18-25";
        if (this.age >= 26 && this.age <= 35) return "26-35";
        if (this.age >= 36 && this.age <= 45) return "36-45";
        if (this.age >= 46 && this.age <= 55) return "46-55";
        if (this.age >= 56 && this.age <= 65) return "56-65";
        return "65+";
      }
      generateBenchmarkExpenses() {
        const cityMultiplier =
          BudgetReportGenerator.CITY_MULTIPLIERS[this.cityType] || 1;
        const ageMultiplier =
          BudgetReportGenerator.AGE_MULTIPLIERS[this._getAgeGroup()] || 1;

        const benchmarkExpenses = {};

        for (const [category, percentage] of Object.entries(
          BudgetReportGenerator.BENCHMARK_EXPENSES
        )) {
          const baseAmount = this.salary * (percentage / 100);
          const adjustedAmount = baseAmount * cityMultiplier * ageMultiplier;

          benchmarkExpenses[category] = {
            percentage: percentage,
            amount: Math.round(adjustedAmount),
          };
        }
        return benchmarkExpenses;
      }
      compareExpenses(userExpenses) {
        const benchmarkExpenses = this.generateBenchmarkExpenses();
        const comparisonReport = {};

        for (const [category, benchmarkData] of Object.entries(
          benchmarkExpenses
        )) {
          const userExpense = userExpenses[category] || 0;

          comparisonReport[category] = {
            benchmark: benchmarkData.amount,
            userExpense: userExpense,
            difference: userExpense - benchmarkData.amount,
            variancePercentage: Math.round(
              (userExpense / benchmarkData.amount - 1) * 100
            ),
          };
        }
        return comparisonReport;
      }
      generateWhatIfScenarios() {
        const scenarios = {
          saveMore: {
            title: "Aggressive Savings Scenario",
            description: "Reduce discretionary expenses and increase savings",
            savings: Math.round(this.salary * 0.3),
          },
          emergencyFund: {
            title: "Emergency Fund Building",
            description: "Create a 6-month emergency fund",
            monthlyContribution: Math.round(this.salary * 0.2),
          },
          investmentGrowth: {
            title: "Long-term Investment Growth",
            description: "Potential investment returns over 10 years",
            annualInvestment: Math.round(this.salary * 0.15),
            projectedGrowth: Math.round(this.salary * 0.15 * 10 * 1.12),
          },
        };
        return scenarios;
      }

      generateReport(userExpenses) {
        return {
          salaryDetails: {
            monthlySalary: this.salary,
            ageGroup: this._getAgeGroup(),
            cityType: this.cityType,
          },
          expensesComparison: this.compareExpenses(userExpenses),
        };
      }
      generateInsights(userExpenses) {
        const comparisonReport = this.compareExpenses(userExpenses);
        const insights = [];
        for (const [category, comparison] of Object.entries(comparisonReport)) {
          if (Math.abs(comparison.variancePercentage) > 30) {
            insights.push({
              category: category,
              type:
                comparison.variancePercentage > 0
                  ? "overspending"
                  : "underspending",
              message: `Your ${category} expenses are ${Math.abs(
                comparison.variancePercentage
              )}% ${
                comparison.variancePercentage > 0 ? "higher" : "lower"
              } than recommended.`,
            });
          }
        }
        return insights;
      }
    }
    if (
      !salary ||
      !age ||
      !cityType ||
      !userExpenses ||
      !data ||
      Object.keys(userExpenses).length === 0
    ) {
      return res.status(400).json({ message: "Missing required fields" });
    }
    const reportGenerator = new BudgetReportGenerator(salary, age, cityType);
    const report = reportGenerator.generateReport(userExpenses);
    const insights = reportGenerator.generateInsights(userExpenses);

    const llmdata = {
      report,
      insights,
      scenarios: reportGenerator.generateWhatIfScenarios(),
    };

    const expenseAnalysis = async () => {
      const Question = llmdata;
      try {
        const llm = new ChatGroq({
          model: "llama3-8b-8192",
          temperature: 0,
          maxTokens: undefined,
          maxRetries: 5,
        });

        const generateQueries = async (data) => {
          try {
            const template = PromptTemplate.fromTemplate(
              `You are a helpful assistant tasked with generating multiple sub-questions related to a given input question.
                        The goal is to break down the input question into a set of sub-problems or sub-questions that can be used to fetch documents from a vector store.
                        Provide the questions in the following structured format, starting with a number followed by a period and a space, then the question text, ending with a question mark. Limit the output to 10 questions, each on a new line.
                        
                        Example Output:
                        
                        1. How can the user categorize their spending to identify unnecessary expenses in rupees?
                        2. What steps can the user take to create a personalized savings plan in rupees?
                        3. How can the user track their expenses in rupees to ensure they stick to a budget?
                        4. What tools or apps can the user use in India to automate their budgeting process?
                        5. How can the user identify patterns in their spending habits over time in rupees?
                        6. What are some practical ways to reduce fixed monthly expenses in India?
                        7. How can the user allocate their income in rupees to achieve specific savings goals?
                        8. What role do emergency funds play in effective money management in India?
                        9. How can the user balance spending on necessities and leisure in rupees?
                        10. How can the user set realistic financial goals in rupees based on their current spending analysis?
                        
                        Search queries related to: {data}:
                        `
            );

            const formattedPrompt = await template.format({ data: data });
            const response = await llm.invoke(formattedPrompt);
            const outputParser = new StringOutputParser();
            const parsedOutput = await outputParser.parse(response);
            const queries = parsedOutput.content.match(/^\d+\.\s.*?\?$/gm);

            return queries || [];
          } catch (error) {
            console.error("Error generating queries:", error);
            return [];
          }
        };

        const retrieveDocuments = async (subQuestions) => {
          try {
            const results = await Promise.all(
              subQuestions.map((q) => retriever2.invoke(q))
            );
            return results;
          } catch (error) {
            console.error("Error retrieving documents:", error);
            return [];
          }
        };

        const reciprocalRankFusion = async (results, k = 60) => {
          try {
            const fusedScores = new Map();

            results.forEach((docs) => {
              docs.forEach((doc, rank) => {
                const docStr = JSON.stringify(doc);
                if (!fusedScores.has(docStr)) {
                  fusedScores.set(docStr, 0);
                }
                fusedScores.set(
                  docStr,
                  fusedScores.get(docStr) + 1 / (rank + k)
                );
              });
            });

            return Array.from(fusedScores.entries())
              .sort((a, b) => b[1] - a[1])
              .slice(0, 5)
              .map(([docStr]) => JSON.parse(docStr));
          } catch (error) {
            console.error("Error in reciprocal rank fusion:", error);
            return [];
          }
        };

        const subQuestions = await generateQueries(Question);

        const allDocuments = await retrieveDocuments(subQuestions);
        const topDocuments = await reciprocalRankFusion(allDocuments);
        console.log(topDocuments);

        const finalTemplate = PromptTemplate.fromTemplate(
          `user expenses data : {user_expenses_data}
              
              Objective: Create an engaging financial narrative with actionable strategies based on user data.
              
              Guidance Requirements:
              Personalized Financial Story
              
              Narrate the user’s financial journey, linking spending to values and goals.
              Identify turning points, opportunities, and highlight surprising insights.
              Tailored Budgeting Techniques
              
              Provide personality-driven approaches (e.g., analytical, visual learners, tech-savvy).
              Include innovative methods like 50/30/20, zero-based, reverse, or adaptive budgeting.
              Explain why they work, step-by-step implementation, and challenges.
              Advanced Saving Strategies
              
              Suggest micro-savings, gamification, automated savings, and reward-based methods.
              Core Purpose: Transform data into a motivating, personalized financial narrative that inspires action, empowers the user, and provides clear, practical steps toward financial growth and security.
              Note: All monetary values and suggestions should be presented in Indian Rupees (₹) instead of dollars ($).
              also use below context for giving response . context : {context}`
        );
        const finalPrompt = await finalTemplate.format({
          user_expenses_data: Question,
          context: topDocuments,
        });
        const outputParser = new StringOutputParser();
        const finalOutput = await outputParser.parse(
          await llm.invoke(finalPrompt)
        );
        return finalOutput.content;
      } catch (error) {
        console.error("Error in chat function:", error);
        return "An error occurred while processing your request.";
      }
    };

    const userData = await UserData.findOne({ _id: data._id });
    let llmres;
    if (!userData) {
      console.error("User data not found.");
      return res.status(404).json({ message: "User data not found." });
    }
    if (!userData.llm || userData.llm === "") {
      llmres = await expenseAnalysis();
      userData.llm = llmres;
      await userData.save();
    } else {
      llmres = userData.llm;
    }

    const resopnse = {
      report,
      insights,
      scenarios: reportGenerator.generateWhatIfScenarios(),
      llmres,
    };
    res.status(200).json({
      resopnse,
    });
  } catch (e) {
    res
      .status(500)
      .json({ message: "Failed to Get Analysis", error: e.message });
  }
});

module.exports = expenseTrackerRouter;
