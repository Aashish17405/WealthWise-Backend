import time
import threading

class GroqKeyRotator:
    def __init__(self, api_keys, cooldown_seconds=300):
        self.api_keys = api_keys
        self.cooldown_seconds = cooldown_seconds
        self.lock = threading.Lock()
        self.key_status = {key: 0 for key in api_keys}  # key: last_used_timestamp

    def get_next_key(self):
        now = time.time()
        with self.lock:
            # Find all keys not in cooldown
            available_keys = [k for k, t in self.key_status.items() if now - t >= self.cooldown_seconds]
            if not available_keys:
                raise Exception("All API keys are in cooldown. Please try again later.")
            # For round-robin, pick the least recently used
            next_key = min(available_keys, key=lambda k: self.key_status[k])
            self.key_status[next_key] = now
            return next_key

# Usage Example
GROQ_API_KEYS = [
    "your_groq_api_key_1",
    "your_groq_api_key_2", "your_groq_api_key_3", # ... up to 20
]
groq_rotator = GroqKeyRotator(GROQ_API_KEYS)

def get_groq_api_key():
    return groq_rotator.get_next_key()

# In your request handler:
import os
os.environ["GROQ_API_KEY"] = get_groq_api_key()

# # app.py
# import os
# os.environ["GROQ_API_KEY"] = "" 

from typing import Type, Literal, Dict, List, Union
from pydantic import BaseModel, Field
from crewai.tools import BaseTool
import requests
from bs4 import BeautifulSoup
from tabulate import tabulate
import re
import yfinance as yf
import json
from serpapi import Client
from flask import Flask, request

# ========== Stock Report Tool ==========

class StockReportInput(BaseModel):
    """Input schema for Stock Report Tool."""
    query_name: Literal["Momentum-Trading", "Scalping", "Position-trading", "swing-trading", "Day-trading"] = Field(
        ...,
        description="Trading strategy for stock screening. Must be one of: 'Momentum-Trading', 'Scalping', 'Position-trading', 'swing-trading', 'Day-trading'"
    )

class StockReportTool(BaseTool):
    """Tool for generating stock reports based on different trading strategies."""

    name: str = "Stock Report Tool"
    description: str = """
    Generates a stock report based on specific trading strategies.
    Available strategies: 'Momentum-Trading', 'Scalping', 'Position-trading', 'swing-trading', 'Day-trading'
    Returns a detailed report with stock metrics and financial data for the top matches.
    """
    args_schema: Type[BaseModel] = StockReportInput

    def _get_symbol_from_bse(self, company_id):
        """Fetch symbol from BSE API."""
        BSE_API_URL = "https://api.bseindia.com/Msource/1D/getQouteSearch.aspx?Type=EQ&text={}&flag=site"
        url = BSE_API_URL.format(company_id)
        headers = {
            "Referer": "https://www.bseindia.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            match = re.search(r"<span>\s*([\w-]+)\s*&nbsp;", response.text)
            if match:
                return match.group(1)  # Extract the stock symbol
        return "Unknown"

    def _get_stock_metrics(self, ticker_symbol):
        """Fetch stock metrics from Yahoo Finance."""
        try:
            stock = yf.Ticker(ticker_symbol)
            info = stock.info
            history = stock.history(period="5y")

            def calculate_growth(current, past):
                if current and past and past != 0:
                    return ((current - past) / past) * 100
                return "N/A"

            try:
                return_1y = calculate_growth(history['Close'].iloc[-1], history['Close'].iloc[-252]) if len(history) > 252 else "N/A"
                return_3y = calculate_growth(history['Close'].iloc[-1], history['Close'].iloc[-756]) if len(history) > 756 else "N/A"
            except (KeyError, IndexError):
                return_1y = return_3y = "N/A"

            metrics = {
                "Return over 1 Year": return_1y,
                "Return over 3 Years": return_3y,
                "P/B Ratio": info.get("priceToBook", "N/A"),
                "EV/EBITDA": info.get("enterpriseToEbitda", "N/A"),
                "Dividend Yield": info.get("dividendYield", "N/A"),
                "P/S Ratio": info.get("priceToSalesTrailing12Months", "N/A"),
                "ROE": info.get("returnOnEquity", "N/A"),
                "Market Cap": info.get("marketCap", "N/A"),
                "Debt/Equity Ratio": info.get("debtToEquity", "N/A")
            }
            return metrics
        except Exception as e:
            print(f"Error fetching data for {ticker_symbol}: {e}")
            return None

    def _run(self, query_name: str) -> str:
        """
        Generate a stock report based on the specified trading strategy.
        """
        print(f"Executing StockReportTool with query_name: {query_name}")

        queries = {
            "Day-trading": """EPS latest quarter > 1.2 * EPS preceding year quarter AND
              EPS latest quarter > 0 AND
              YOY Quarterly sales growth > 25 AND
              EPS last year > EPS preceding year AND
              EPS > EPS last year AND
              Profit growth 3Years > 25 AND
              Return on equity > 17 AND
              Down from 52w high < 18 AND
              Market Capitalization > 5 """,
            "swing-trading": """PEG Ratio > 2 AND
                Debt to equity < 0.5 AND
                Market Capitalization > 5000 AND
                52w Index >75 AND
                Average return on equity 5Years > 0""",
            "Position-trading": """Market Capitalization  > 1000 AND
                OPM 5Year >Price to Earning AND
                Interest Coverage Ratio >3 AND Debt
                to equity < 1 AND Pledged percentage =0""",
            "Scalping": """Volume 1week average > 2*(Volume 1month average) AND Volume > 1000000""",
            "Momentum-Trading": """Down from 52w high <= 6 AND
                Current price > 20 AND
                net profit > 30 and
                Market Capitalization > 500""",
            "Long-term-investment":"""Market Capitalization >3000 AND
                Return on invested capital >15 AND
                Average return on capital employed 5Years >14 AND
                Average return on equity 5Years >14 AND
                Average return on capital employed 3Years >14 AND
                Average return on equity 3Years >14 AND
                Sales growth 5Years >8 AND
                Sales growth 3Years >8 AND
                Profit growth 5Years >10 AND
                Profit growth 3Years >14 AND
                Debt to equity <0.6 AND
                Current ratio >1"""
        }

        query = queries.get(query_name)
        print(query)
        urls={
            "Day-trading":"https://www.screener.in/screens/481424/best-companies-for-intraday/?order=asc",
            "Momentum-Trading":"https://www.screener.in/screens/805502/best-momentum-stocks/",
            "Long-term-investment":"https://www.screener.in/screens/779133/best-stock-for-long-term-investment/",
            "Scalping":"https://www.screener.in/screens/611041/scalping-picks/",
            "Position-trading":"https://www.screener.in/screens/283302/stocks-for-positional-trade",
            "swing-trading":"https://www.screener.in/screens/195637/swing-trading-growth-stocks"
        }
        if query is None:
            return f"Invalid query name: {query_name}. Please use one of: 'Momentum-Trading', 'Scalping', 'Position-trading', 'swing-trading', 'Day-trading'"

        base_url = urls.get(query_name)
        print(base_url)
        cookies = {
            "csrftoken": "8JX2VgRbXPWvhKxzY2I0aKmsgRLdkxsi",  # Replace with valid values
            "sessionid": "wb0tu8gqfulvl6423btiq60g8oujzeao"
        }
        params = {"sort": "", "order": "", "source_id": "97687", "query": query}
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Referer": "https://www.screener.in/screen/raw/",
        }

        response = requests.get(base_url, headers=headers, cookies=cookies, params=params)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            table = soup.find('table')

            if table:
                rows = table.find_all('tr')
                headers = ["Symbol"] + [th.text.strip() for th in rows[0].find_all('th')]
                data = []

                for row in rows[1:min(len(rows), 11)]:
                    cells = row.find_all('td')
                    row_data = [cell.text.strip() for cell in cells]

                    symbol = "-"
                    link = row.find('a', href=True)
                    if link:
                        href = link['href']
                        match1 = re.search(r"/company/([^/]+)/consolidated/", href)
                        match2 = re.search(r"/company/([^/]+)/?$", href)
                        match3 = re.search(r"/company/(\d+)", href)

                        if match1:
                            symbol = match1.group(1) + ".NS"
                        elif match3:
                            company_id = match3.group(1)
                            symbol = self._get_symbol_from_bse(company_id) + ".BO"
                        elif match2:
                            symbol = match2.group(1) + ".NS"

                    data.append([symbol] + row_data)

                headers += ["Return over 1 Year", "Return over 3 Years", "P/B Ratio", "EV/EBITDA", "Dividend Yield",
                            "P/S Ratio", "ROE", "Market Cap", "Debt/Equity Ratio"]
                report1 = f"""
                ****** STOCK REPORT: {query_name} ******
                Query Conditions:
                -----------------
                {query}
                base url: {base_url}
                Retrieved {len(data)} stock entries.
                Data Table:
                -----------
                {tabulate(data, headers=headers, tablefmt="grid")}
                *****************
                """
                print(report1)
                data = data[:7]

                report_data = {
                    "query_name": query_name,
                    "query": queries.get(query_name),
                    "retrieved_count": len(data),
                    "data": data
                }
                report_json = json.dumps(report_data, indent=None, default=str)
                return report_json
            else:
                return "No table found on the page."
        else:
            return f"Failed to retrieve data. Status code: {response.status_code}"

# ========== Sentiment Analysis Tool ==========

def nlpe(sentence):
    API_URL = "https://router.huggingface.co/hf-inference/models/ProsusAI/finbert"
    headers = {
        "Authorization": f"Bearer your_huggingface_api_key",
        "Content-Type": "application/json"
    }
    payload = {
        "inputs": sentence
    }
    response = requests.post(API_URL, headers=headers, json=payload)
    print(response.text)
    return response.json()

def print_sentiment_report(sentiment_reports):
    """Prints sentiment reports in a formatted, readable way."""
    for company, data in sentiment_reports.items():
        print("-" * 50)
        print(f"Company: {data['company_name']}")
        print("-" * 50)
        print(f"Status: {data['status']}")
        print(f"Reputation Score: {data['reputation_score']}")
        print("\nSentiment Distribution:")
        for sentiment, percentage in data['sentiment_distribution'].items():
            print(f"  {sentiment}: {percentage:.2f}%")
        print("\nTop Articles:")
        for i, article in enumerate(data['top_articles']):
            print(f"  {i+1}. Title: {article['title']}")
            if article.get('link'):
                print(f"     Link: {article['link']}")
            print(f"     Sentiment: {article['sentiment']}")
            print(f"     Score: {article['score']:.4f}")
            print("-" * 20)
        print("\n")

class SentimentAnalysisInput(BaseModel):
    """Input schema for Sentiment Analysis Tool."""
    companies: List[str] = Field(
        ...,
        description="List of company names to analyze sentiment for."
    )

class CompanySentimentTool(BaseTool):
    """Tool for analyzing market sentiment and company reputation from news articles."""

    name: str = "Company Sentiment Analysis Tool"
    description: str = """
    Analyzes market sentiment and reputation for companies based on recent news articles.
    Uses FinBERT model for sentiment analysis and retrieves news from Google News.
    Returns sentiment scores, reputation analysis, and key articles for each company.
    """
    args_schema: Type[BaseModel] = SentimentAnalysisInput

    def _run(self, companies: List[str]) -> dict:
        """
        Run sentiment analysis for the specified companies.
        """
        sentiment_reports = {}
        sentiment_reports1 = {}
        num_articles = 3

        for company in companies:
            try:
                serp_client = Client(api_key="your_serp_api_key")
                results = serp_client.search({
                    'engine': 'google_news',
                    'q': company,
                    'gl': 'in',
                    'hl': 'en'
                })

                news_articles = results.get('news_results', [])[:num_articles]
                if not news_articles:
                    sentiment_reports[company] = {
                        "status": "error",
                        "message": f"No news articles found for {company}"
                    }
                    continue

                sentiment_counts = {'Positive': 0, 'Neutral': 0, 'Negative': 0}
                analyzed_articles = []

                for article in news_articles:
                    title = article['title']
                    sentiment_result = nlpe(title)[0][0]
                    sentiment = sentiment_result['label'].capitalize()
                    score = sentiment_result['score']

                    sentiment_counts[sentiment] += 1
                    analyzed_articles.append({
                        'title': title,
                        'link': article.get('link', ''),
                        'sentiment': sentiment,
                        'score': round(score, 4)
                    })

                total_articles = len(news_articles)
                sentiment_distribution = {
                    sentiment: round((count / total_articles) * 100, 2)
                    for sentiment, count in sentiment_counts.items()
                }

                sentiment_weights = {'Positive': 1, 'Neutral': 0, 'Negative': -1}
                reputation_score = sum([sentiment_weights[art['sentiment']] for art in analyzed_articles])
                reputation_score = (reputation_score / total_articles) * 50 + 50

                sentiment_reports[company] = {
                    "company_name": company,
                    "reputation_score": round(reputation_score, 2),
                    "sentiment_distribution": sentiment_distribution,
                    "top_articles": [article['title'] for article in analyzed_articles[:3]]
                }
                sentiment_reports1[company] = {
                    "status": "success",
                    "company_name": company,
                    "reputation_score": round(reputation_score, 2),
                    "sentiment_distribution": sentiment_distribution,
                    "top_articles": analyzed_articles[:3]
                }

                print_sentiment_report({company: sentiment_reports1[company]})

            except Exception as e:
                sentiment_reports[company] = {
                    "status": "error",
                    "message": f"Error analyzing {company}: {str(e)}"
                }

        print("Final Sentiment Reports:")
        print(json.dumps(sentiment_reports1, indent=2))
        return sentiment_reports

# ========== CrewAI Agents and Tasks ==========

try:
    from crewai import Agent, Task, Crew, LLM, Process
except ImportError:
    print("crewai not installed. Skipping agent setup. (For demo, this is optional if you use only Flask routes.)")
    pass

try:
    stock_report_tool = StockReportTool()
    sentiment_tool = CompanySentimentTool()

    llm_70b = LLM(model="groq/llama-3.3-70b-versatile")
    llm_8b = LLM(model="groq/llama-3.1-8b-instant")
    llm_32b = LLM(model="groq/deepseek-r1-distill-llama-70b")

    financial_analyst_agent = Agent(
        role="Financial Analyst",
        goal="Analyze the user's financial condition and determine the budget and risk level for investment.",
        backstory="You are a seasoned financial analyst with expertise in evaluating financial conditions and determining appropriate investment strategies based on income, expenses, savings, and risk tolerance.",
        llm=llm_8b,
        verbose=False
    )

    financial_metrics_agent = Agent(
        role="Financial Metrics Analyst",
        goal="Fetch a list of stocks with financial metrics based on the user's strategy, risk tolerance, and financial analysis.",
        backstory="You are a financial metrics expert who specializes in analyzing stocks based on financial data. You use advanced tools to fetch and evaluate stock metrics, ensuring the recommendations align with the user's strategy and risk tolerance.",
        tools=[stock_report_tool],
        llm=llm_70b,
        verbose=True
    )

    sentiment_recommendation_agent = Agent(
        role="Sentiment and Recommendation Analyst",
        goal="Analyze market sentiment and recommend the top 5 stocks based on financial metrics and sentiment analysis.",
        backstory="You are an expert in analyzing market sentiment and company reputation. You combine financial metrics and sentiment analysis to provide well-rounded stock recommendations that align with the user's strategy and risk tolerance.",
        tools=[sentiment_tool],
        llm=llm_32b,
        verbose=True
    )

    financial_analysis_task = Task(
        description="Analyze the user's financial condition metrics and determine the budget and risk level for investment.",
        agent=financial_analyst_agent,
        expected_output="A concise report containing: 1. Input details (income, expenses, savings, investment amount, risk tolerance). 2. 2-3 key conclusions (e.g., recommended budget, risk level)."
    )

    financial_metrics_task = Task(
        description="Based on the previous Financial Analyst's recommendations, fetch and analyze appropriate stocks.",
        agent=financial_metrics_agent,
        expected_output="A detailed report containing: 1. Names of the top stocks. 2. Stock tickers. 3. Key financial metrics for each stock. 4. Explanation of why these stocks were selected."
    )

    sentiment_recommendation_task = Task(
        description="Analyze market sentiment and recommend the top 5 stocks based on financial metrics and sentiment analysis.",
        agent=sentiment_recommendation_agent,
        expected_output="A detailed report containing: 1. Top 5 recommended stocks. 2. For each stock: Summary of financial metrics, sentiment analysis, detailed reasoning, risk assessment."
    )

    financial_crew = Crew(
        agents=[financial_analyst_agent, financial_metrics_agent, sentiment_recommendation_agent],
        tasks=[financial_analysis_task, financial_metrics_task, sentiment_recommendation_task],
        verbose=False,
        process=Process.sequential,
        manager_llm=llm_8b
    )
except NameError:
    financial_crew = None

# ========== Flask App ==========

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello, World!"

# Dummy financial_crew.kickoff function (replace with actual logic if crewai is available)
class financial_crew_dummy:
    @staticmethod
    def kickoff(inputs):
        class Result:
            raw = f"Processed input: {inputs}"
        return Result()

@app.route('/stockRecommandation', methods=['POST'])
def stock_recommendation():
    try:
        content = request.json
        print(f"Received content: {content['input']}")
        if financial_crew is not None:
            result = financial_crew.kickoff(inputs=content['input'])
        else:
            result = financial_crew_dummy.kickoff(inputs=content['input'])
        return {"status": "success", "received": result.raw + "\n\n "}, 200
    except Exception as e:
        print(f"Error: {e}")
        return {"status": "error", "message": str(e)}, 500

if __name__ == '__main__':
    app.run(port=5000)
