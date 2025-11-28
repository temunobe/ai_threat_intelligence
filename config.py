# config.py The configuration settings for the application

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / 'data'
LOG_DIR = BASE_DIR / 'logs'
MODELS_DIR = BASE_DIR / 'models'

for directory in [DATA_DIR, LOG_DIR, MODELS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

DARKWEB_ENABLED = os.getenv('DARKWEB_ENABLED', 'False').lower() == 'true'
TOR_PROXY = os.getenv('TOR_PROXY', 'socks5h://127.0.0.1:9050')

# API Keys
TWITTER_API_KEY = os.getenv('TWITTER_API_KEY', '')
TWITTER_API_SECRET = os.getenv('TWITTER_API_SECRET', '')
TWITTER_ACCESS_TOKEN = os.getenv('TWITTER_ACCESS_TOKEN', '')
TWITTER_ACCESS_SECRET = os.getenv('TWITTER_ACCESS_SECRET', '')

REDDIT_CLIENT_ID = os.getenv('REDDIT_CLIENT_ID', '')
REDDIT_CLIENT_SECRET = os.getenv('REDDIT_CLIENT_SECRET', '')
REDDIT_USER_AGENT = os.getenv('REDDIT_USER_AGENT', 'ThreatIntel/1.0')

# Neo4J
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD', 'password')

# Model
MODEL_NAME = "meta-llama/Llama-4-Scout-17B-16E-Instruct"
MAX_LEGNTH = 512
BATCH_SIZE = 8
LEARNING_RATE = 2e-5
NUM_EPOCHS = 3

# Entity labels for NER
ENTITY_LABELS = [
    "O",
    "B-IOC",
    "I-IOC",
    "B-MALWARE",
    "I-MALWARE",
    "B-CVE",
    "I-CVE",
    "B-ACTOR",
    "I-ACTOR",
    "B-TTP",
    "I-TTP"
]

# MITRE ATT&CK
MITRE_DATA_PATH = DATA_DIR / 'mitre_attack.json'
MITRE_SIMILARITY_THRESHOLD = 0.7

# Alerts
URGENCY_KEYWORDS = [
    'exploit',
    'zero-day',
    'critical',
    'ransomware',
    'breach',
    'vulnerability',
    'attack',
    'malware',
    'apt',
    'threat actor',
    'compromise'
]

# Clustering settings
DBSCAN_EPS = 0.3
DBSCAN_MIN_SAMPLES = 2
ANOMALY_CONTAMINATION = 0.1

# Dashboard
DASHBOARD_HOST = '0.0.0.0'
DASHBOARD_PORT = 8501

# Logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FORMAT = '<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>'