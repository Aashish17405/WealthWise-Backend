const { Pinecone } = require("@pinecone-database/pinecone");
const { PineconeStore } = require("@langchain/pinecone");
const { PineconeEmbeddings } = require("@langchain/pinecone");

let retriever1 = null;
let retriever2 = null;

// Simple mutex to prevent concurrent API key modifications
let isInitializing = false;
const initQueue = [];

async function withApiKey(apiKey, asyncFunction) {
  return new Promise((resolve, reject) => {
    const execute = async () => {
      if (isInitializing) {
        // If another function is initializing, wait for it to complete
        initQueue.push(() => execute());
        return;
      }

      isInitializing = true;
      const originalApiKey = process.env.PINECONE_API_KEY;

      try {
        process.env.PINECONE_API_KEY = apiKey;
        const result = await asyncFunction();
        resolve(result);
      } catch (error) {
        reject(error);
      } finally {
        // Restore original API key
        if (originalApiKey !== undefined) {
          process.env.PINECONE_API_KEY = originalApiKey;
        } else {
          delete process.env.PINECONE_API_KEY;
        }

        isInitializing = false;

        // Process next item in queue
        if (initQueue.length > 0) {
          const nextFunction = initQueue.shift();
          setTimeout(nextFunction, 0);
        }
      }
    };

    execute();
  });
}

// async function get_retriever() {
//   process.env.PINECONE_API_KEY = process.env.PINECONE_API_KEY1;
//   const PINECONE_INDEX = "knowledge-retrival";
//   const pinecone = new Pinecone();
//   const pineconeIndex = pinecone.Index(PINECONE_INDEX);
//   const embeddings = new PineconeEmbeddings({
//     model: "multilingual-e5-large",
//   });
//   const vectorStore = await PineconeStore.fromExistingIndex(embeddings, {
//     pineconeIndex,
//     maxConcurrency: 5,
//   });
//   retriever1 = vectorStore.asRetriever();
//   process.env.PINECONE_API_KEY = "";
// }

async function get_retriever() {
  if (!process.env.PINECONE_API_KEY1) {
    throw new Error("PINECONE_API_KEY1 environment variable is not set");
  }

  return await withApiKey(process.env.PINECONE_API_KEY1, async () => {
    try {
      const PINECONE_INDEX = "knowledge-retrieval";
      const pinecone = new Pinecone();

      console.log("Checking available indexes...");
      const indexList = await pinecone.listIndexes();
      console.log(
        "Available indexes:",
        indexList.indexes?.map((idx) => idx.name) || []
      );

      const indexExists = indexList.indexes?.some(
        (idx) => idx.name === PINECONE_INDEX
      );

      if (!indexExists) {
        console.log(`Index "${PINECONE_INDEX}" not found. Creating it...`);

        await pinecone.createIndex({
          name: PINECONE_INDEX,
          dimension: 1024,
          metric: "cosine",
          spec: {
            serverless: {
              cloud: "aws",
              region: "ap-south-1a", // Change to your preferred region
            },
          },
        });

        console.log(`Index "${PINECONE_INDEX}" created successfully`);

        console.log("Waiting for index to be ready...");
        await new Promise((resolve) => setTimeout(resolve, 10000));
      }

      const pineconeIndex = pinecone.Index(PINECONE_INDEX);

      // Create embeddings AFTER setting the API key
      const embeddings = new PineconeEmbeddings({
        model: "multilingual-e5-large",
      });

      console.log("Creating vector store...");
      const vectorStore = await PineconeStore.fromExistingIndex(embeddings, {
        pineconeIndex,
        maxConcurrency: 5,
      });

      retriever1 = vectorStore.asRetriever({
        k: 5,
        searchType: "similarity",
      });

      console.log("Retriever initialized successfully");
      return retriever1;
    } catch (error) {
      console.error("Error initializing retriever:", error);

      if (error.message.includes("404")) {
        console.error(
          "Index not found. Please check the index name and ensure it exists in your Pinecone dashboard."
        );
      } else if (error.message.includes("401")) {
        console.error("Authentication failed. Please check your API key.");
      } else if (error.message.includes("403")) {
        console.error(
          "Access forbidden. Please check your API key permissions."
        );
      }

      throw error;
    }
  });
}

async function get_retrieverExpense() {
  if (!process.env.PINECONE_API_KEY2) {
    throw new Error("PINECONE_API_KEY2 environment variable is not set");
  }

  return await withApiKey(process.env.PINECONE_API_KEY2, async () => {
    try {
      const PINECONE_INDEX = "expense";
      const pinecone = new Pinecone();
      const pineconeIndex = pinecone.Index(PINECONE_INDEX);

      // Create embeddings AFTER setting the API key
      const embeddings = new PineconeEmbeddings({
        model: "multilingual-e5-large",
      });

      const vectorStore = await PineconeStore.fromExistingIndex(embeddings, {
        pineconeIndex,
        maxConcurrency: 5,
      });

      retriever2 = vectorStore.asRetriever();

      console.log("Expense retriever initialized successfully");
      return retriever2;
    } catch (error) {
      console.error("Error initializing expense retriever:", error);
      throw error;
    }
  });
}

module.exports = {
  get_retriever,
  get_retrieverExpense,
  retriever1,
  retriever2,
};
