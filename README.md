<p align="center">
    <img src="https://github.com/user-attachments/assets/936e0ad8-e308-4f0e-ae6d-5ac23a321e9f" align="center" width="30%">
</p>
<p align="center"><h1 align="center">WEALTHWISE BACKEND</h1></p>
<p align="center">
    <a href="https://wealthwisee.live/" target="_blank">
        <img src="https://img.shields.io/badge/Live%20Demo-wealthwisee.live-brightgreen" alt="Live Demo">
    </a>
    <img src="https://img.shields.io/github/last-commit/Aashish17405/WealthWise-Backend?style=default&logo=git&logoColor=white&color=0080ff" alt="last-commit">
    <img src="https://img.shields.io/github/languages/top/Aashish17405/WealthWise-Backend?style=default&color=0080ff" alt="repo-top-language">
    <img src="https://img.shields.io/github/languages/count/Aashish17405/WealthWise-Backend?style=default&color=0080ff" alt="repo-language-count">
</p>
<p align="center"><!-- default option, no dependency badges. -->
</p>
<p align="center">
	<!-- default option, no dependency badges. -->
</p>
<br>

## 🔗 Table of Contents

- [📍 Overview](#-overview)
- [👾 Features](#-features)
- [🤖 Agentic Workflow for Stock Recommendation](#-agentic-workflow-for-stock-recommendation)
- [📁 Project Structure](#-project-structure)
  - [📂 Project Index](#-project-index)
- [🚀 Getting Started](#-getting-started)
  - [☑️ Prerequisites](#-prerequisites)
  - [⚙️ Installation](#-installation)
- [🙌 Contributors](#-contributors)

---

## 📍 Overview

WealthWise is a comprehensive financial management platform that helps users track expenses, manage investments, and get personalized financial recommendations. The backend is built with Node.js & Express.js, providing a robust REST API that powers the WealthWise application.

🔗 **Live Demo:** [https://wealthwisee.live/](https://wealthwisee.live/)

---

## 👾 Features

### 🔐 User Authentication & Security

- Google OAuth authentication for seamless login
- JWT-based authorization for secure API access
- reCAPTCHA integration to prevent bot-based attacks

### 📊 Financial Data Processing & AI Analytics

- AI-driven personalized investment recommendations based on income, risk appetite & market trends
- Expense & savings tracking system for financial planning
- Real-time stock market simulation with virtual currency transactions

### 💹 Investment & Market Insights

- AI-powered stock, mutual fund, and fixed deposit recommendations
- Real-time financial analytics with predictive insights
- Custom portfolio management API for tracking investments

### 🏗️ Secure & Scalable Architecture

- MongoDB (Mongoose) for flexible & scalable data storage
- Express.js API endpoints for seamless integration with the frontend
- Data encryption & secure API routes for financial data protection

---
### 🤖 Agentic Workflow for Stock Recommendation
<img src="https://github.com/user-attachments/assets/2edea25c-f727-4d8c-8ed4-f62ca12acee6" align="center"/>

---

## 📁 Project Structure

```sh
WealthWise-Backend/
├── Agents/                 # AI agent implementations
│   ├── app.py             # Main agent application
│   └── requirements.txt   # Python dependencies for agents
├── models/                # MongoDB schemas and models
│   ├── UserData.js        # User data schema
│   ├── Signup.js          # User authentication schema
│   └── allschemas.js      # Additional database schemas
├── routes/                # API route handlers
│   ├── authRoutes.js      # Authentication endpoints
│   ├── expenseTrackerRoutes.js  # Expense tracking endpoints
│   ├── virtualStockRoutes.js    # Virtual stock portfolio endpoints
│   ├── recommendationRoutes.js  # Financial recommendation endpoints
│   └── ragRouter.js       # Document processing endpoints
├── utils/                 # Utility functions
│   └── utils.js           # Common utility functions
├── .env.example          # Environment variables template
├── package.json          # Node.js dependencies
└── index.js              # Main application entry point
```

### 📂 Project Index

<details open>
	<summary><b><code>WEALTHWISE_BACKEND/</code></b></summary>
	<details> <!-- __root__ Submodule -->
		<summary><b>__root__</b></summary>
		<blockquote>
			<table>
			<tr>
				<td><b><a href='https://github.com/Abhiyantrana-Navonmesakah/Wealthwise_backend/blob/master/package-lock.json'>package-lock.json</a></b></td>
				<td><code>Locks dependency versions for consistent installations</code></td>
			</tr>
			<tr>
				<td><b><a href='https://github.com/Abhiyantrana-Navonmesakah/Wealthwise_backend/blob/master/vercel.json'>vercel.json</a></b></td>
				<td><code>Configuration file for Vercel deployment settings</code></td>
			</tr>
			<tr>
				<td><b><a href='https://github.com/Abhiyantrana-Navonmesakah/Wealthwise_backend/blob/master/index.js'>index.js</a></b></td>
				<td><code>Main application entry point and server configuration</code></td>
			</tr>
			<tr>
				<td><b><a href='https://github.com/Abhiyantrana-Navonmesakah/Wealthwise_backend/blob/master/package.json'>package.json</a></b></td>
				<td><code>Project metadata and dependency management</code></td>
			</tr>
			</table>
		</blockquote>
	</details>
	<details> <!-- models Submodule -->
		<summary><b>models</b></summary>
		<blockquote>
			<table>
			<tr>
				<td><b><a href='https://github.com/Abhiyantrana-Navonmesakah/Wealthwise_backend/blob/master/models/allschemas.js'>allschemas.js</a></b></td>
				<td><code>MongoDB schemas for data models</code></td>
			</tr>
			</table>
		</blockquote>
	</details>
	<details> <!-- routes Submodule -->
		<summary><b>routes</b></summary>
		<blockquote>
			<table>
			<tr>
				<td><b><a href='https://github.com/Abhiyantrana-Navonmesakah/Wealthwise_backend/blob/master/routes/AllRoutes.js'>AllRoutes.js</a></b></td>
				<td><code>API route definitions and handlers</code></td>
			</tr>
			</table>
		</blockquote>
	</details>
</details>

---

## 🚀 Getting Started

### ☑️ Prerequisites

- Node.js (v16 or higher)
- npm (v8 or higher)
- MongoDB Atlas account
- Python 3.8+ (for AI agents)
- API keys for:
  - Groq API
  - Pinecone
  - reCAPTCHA

### ⚙️ Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Aashish17405/WealthWise-Backend.git
   cd WealthWise-Backend
   ```
Install Wealthwise_backend using one of the following methods:

**Build from source:**

1. Clone the Wealthwise_backend repository:

```sh
❯ git clone https://github.com/Aashish17405/WealthWise-Backend.git
```

2. Navigate to the project directory:

```sh
❯ cd WealthWise-Backend
```

3. Install the project dependencies:

**Using `npm`**

```sh
❯ npm install
```

## Contributors

Anurag [@AnuragNarsingoju](https://github.com/AnuragNarsingoju)

Nagasai [@NagasaiPraneeth](https://github.com/NagasaiPraneeth)

Aashish [@Aashish17405](https://github.com/Aashish17405)

Abhilash [@AbhiGX](https://github.com/Abhi-GX)
