# from flask import Flask, render_template, jsonify, request
# from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import requests
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def fetch_cves(start_index=0, results_per_page=2):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "startIndex": start_index,
        "resultsPerPage": results_per_page
    }
    headers = {
        "apiKey": "d99a6fcc-3f60-4dd7-ae63-2d5c8a4388b4"  # Replace with your API key
    }

    logger.info(f"Fetching CVEs: start_index={start_index}, results_per_page={results_per_page}")

    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Error fetching CVEs: {e}")
        return None

print(fetch_cves())