const { get_retriever } = require("../utils/utils");
const { ChatGroq } = require("@langchain/groq");
const { PromptTemplate } = require("@langchain/core/prompts");
const { StringOutputParser } = require("@langchain/core/output_parsers");
const express = require("express");
const ragRouter = express.Router();

let retriever1 = null;

async function initializeRetrievers() {
  try {
    retriever1 = await get_retriever();
    console.log("Retrievers initialized successfully");
  } catch (error) {
    console.error("Failed to initialize retrievers:", error);
    throw error;
  }
}

// Initialize retrievers immediately
initializeRetrievers().catch(console.error);

async function chat(Question) {
  try {
    // Check if retrievers are initialized
    if (!retriever1) {
      return "System is still initializing. Please try again in a few moments.";
    }

    const llm = new ChatGroq({
      model: "llama-3.3-70b-versatile",
      temperature: 0,
      maxTokens: undefined,
      maxRetries: 5,
    });

    const generateQueries = async (question) => {
      try {
        const prompt = PromptTemplate.fromTemplate(
          `You are a helpful assistant that generates exactly three distinct and concise questions related to an input question.
          The goal is to break the input question into three self-contained queries that can be answered independently. Ensure that:
          1. Each query is a complete question.
          2. No additional explanation or context is included.
    
          Input Question: {question}
          Generated Queries:
          1.
          2.
          3.`
        );

        const formattedPrompt = await prompt.format({ question: Question });
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
        if (!retriever1) {
          console.error("Retriever1 is not initialized yet");
          return [];
        }

        const results = await Promise.all(
          subQuestions.map((q) => retriever1.invoke(q))
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
            fusedScores.set(docStr, fusedScores.get(docStr) + 1 / (rank + k));
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

    const subQuestions = await generateQueries();
    console.log(subQuestions);

    const allDocuments = await retrieveDocuments(subQuestions);

    const topDocuments = await reciprocalRankFusion(allDocuments);
    // console.log(topDocuments)

    const template = PromptTemplate.fromTemplate(
      `You are a financial advisory helper chatbot, "Niveshak," which understands the provided context below and gives a beautiful, understandable response to the user by following these guidelines:

        Question: {question}  

        1. **If the question does NOT relate to finance or personal finance, respond ONLY with:**  
          **"As an AI Chatbot, I cannot provide information on that topic."**  

        2. **If the question includes personal financial details of any individual, such as their investments, assets, net worth, or private financial information, respond ONLY with:**  
          **"I'm sorry, but I cannot provide personal financial details about individuals."**  

        3. **If the user’s question is related to greetings, just greet them appropriately.**  

        4. **If the question is related to finance, provide a comprehensive answer that includes (as applicable):**  
          - A definition  
          - Real-life examples  
          - Personal finance calculations  

        5. **Give responses based on the question. You may include or exclude the above points based on the question’s needs. If the question doesn't require these points, provide only the necessary response.**  

        6. **Use the below context for replying, and always perform calculations in Indian Rupees.**  

        Context: {context} `
    );

    const finalPrompt = await template.format({
      question: Question,
      context: topDocuments,
    });
    //console.log(finalPrompt)
    const outputParser = new StringOutputParser();
    const finalOutput = await outputParser.parse(await llm.invoke(finalPrompt));
    return finalOutput.content;
  } catch (error) {
    console.error("Error in chat function:", error);
    return "An error occurred while processing your request.";
  }
}

ragRouter.post("/", async (req, res) => {
  try {
    // Wait for retrievers to be initialized (with timeout)
    let attempts = 0;
    const maxAttempts = 15; // 15 seconds timeout

    while (!retriever1 && attempts < maxAttempts) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      attempts++;
    }

    if (!retriever1) {
      return res.status(503).json({
        error: "Service temporarily unavailable. Please try again later.",
      });
    }

    let { question } = req.body;
    question = question.toLowerCase();
    const answer = await chat(question);
    res.status(200).json({ answer });
  } catch (error) {
    console.error("Error in RAG router:", error);
    res.status(400).json({ error: error.message });
  }
});

// Health check endpoint
ragRouter.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    retrieversInitialized: {
      retriever1: !!retriever1,
    },
  });
});

module.exports = ragRouter;
