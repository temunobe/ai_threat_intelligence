# data_collector.py
# Module for collecting data from various sources
import requests
import praw
import tweepy
import config

from abc import ABC, abstractmethod
from typing import List, Dict
from loguru import logger
from bs4 import BeautifulSoup

class BaseCollector(ABC):
    @abstractmethod
    def collect(self, query: str, limit: int = 100) -> List[Dict]:
        pass

class DarkWebCollector(BaseCollector):
    def __init__(self, proxy: str = None):
        self.proxy = proxy or config.TOR_PROXY
        self.session = requests.Session()
        self.session.proxies = {
            'http': self.proxy,
            'https': self.proxy
        }

    def collect(self, query: str, limit: int = 100) -> List[Dict]:
        if not config.DARKWEB_ENABLED:
            logger.warning("Dark web collection is disabled in the configuration.")
            return []
        
        url = f"http://darkwebsearchengine.onion/search?q={query}&limit={limit}"
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            results = []
            for item in soup.select('.result-item')[:limit]:
                title = item.select_one('.result-title').text
                link = item.select_one('.result-link')['href']
                snippet = item.select_one('.result-snippet').text
                results.append({'title': title, 'link': link, 'snippet': snippet})
            return results
        except requests.RequestException as e:
            logger.error(f"Error collecting data from dark web: {e}")
            return []
        
class TwitterCollector(BaseCollector):
    def __init__(self):
        if not all([config.TWITTER_API_KEY, config.TWITTER_API_SECRET,
                    config.TWITTER_ACCESS_TOKEN, config.TWITTER_ACCESS_SECRET]):
            logger.warning("Twitter API credentials are not configured.")
            self.client = None
            return
        
        auth = tweepy.OAuth1UserHandler(
            config.TWITTER_API_KEY,
            config.TWITTER_API_SECRET
        )
        auth.set_access_token(
            config.TWITTER_ACCESS_TOKEN,
            config.TWITTER_ACCESS_SECRET
        )
        self.client = tweepy.API(auth)

    def collect(self, query: str, limit: int = 100) -> List[Dict]:
        if not self.client:
            logger.warning("Twitter client is not initialized due to missing credentials.")
            return []
        
        results = []
        try:
            tweets = self.client.search_tweets(q=query, lang="en", count=limit, tweet_mode='extended')
            
            for tweet in tweets:
                results.append({
                    'source': 'twitter',
                    'text': tweet.full_text,
                    'author': tweet.user.screen_name,
                    'timestamp': tweet.created_at.isoformat(),
                    'url': f"https://twitter.com/{tweet.user.screen_name}/status/{tweet.id}"
                })

            logger.info(f"Collected {len(results)} tweets for query: {query}")
        except tweepy.TweepError as e:
            logger.error(f"Error collecting data from Twitter: {e}")
        return results
    
class RedditCollector(BaseCollector):
    def __init__(self):
        if not all([config.REDDIT_CLIENT_ID, config.REDDIT_CLIENT_SECRET, config.REDDIT_USER_AGENT]):
            logger.warning("Reddit API credentials are not configured.")
            self.reddit = None
            return
        
        self.reddit = praw.Reddit(
            client_id=config.REDDIT_CLIENT_ID,
            client_secret=config.REDDIT_CLIENT_SECRET,
            user_agent=config.REDDIT_USER_AGENT
        )

    def collect(self, query: str, limit: int = 100) -> List[Dict]:
        if not self.reddit:
            logger.warning("Reddit client is not initialized due to missing credentials.")
            return []
        
        results = []
        subreddits = ['cybersecurity', 'netsec', 'malware', 'hacking']
        try:
            for subreddit_name in subreddits:
                subreddit = self.reddit.subreddit(subreddit_name)

                for post in subreddit.search(query, limit=limit//len(subreddits)):
                    results.append({
                        'source': 'reddit',
                        'title': post.title,
                        'text': post.selftext,
                        'author': str(post.author),
                        'subreddit': subreddit_name,
                        'timestamp': post.created_utc,
                        'url': f"https://reddit.com{post.permalink}",
                        'score': post.score
                    })

            logger.info(f"Collected {len(results)} Reddit posts for query: {query}")
        except Exception as e:
            logger.error(f"Error collecting data from Reddit: {e}")
        return results
    
class BlogCollector(BaseCollector):
    def __init__(self):
        self.sources = [
            'https://krebs-on-security.com',
            'https://www.darkreading.com',
            'https://www.threatpost.com',
            'https://www.securityweek.com',
            'https://www.cyberscoop.com',
            'https://www.infosecurity-magazine.com',
            'https://krebsonsecurity.com',
            'https://www.schneier.com/blog/'
        ]

    def collect(self, query: str, limit: int = 100) -> List[Dict]:
        results = []
        for source in self.sources:
            try:
                response = requests.get(source, timeout=10)
                response.raise_for_status()
                soup = BeautifulSoup(response.content, 'html.parser')
                articles = soup.find_all('article', limit//len(self.sources))
                
                for article in articles:
                    title = article.find('h2') or article.find('h1')
                    content = article.find('div', class_='entry-content') or article.find('div', class_='post-content')

                    if article in content:
                        results.append({
                            'source': 'blog',
                            'origin': source,
                            'title': title.get_text(strip=True),
                            'text': content.get_text(strip=True),
                            'url': article.find('a')['href'] if article.find('a') else source
                        })
                logger.info(f"Collected articles from blog: {source}")
            except requests.RequestException as e:
                logger.error(f"Error collecting data from blog {source}: {e}")
        return results
    
class STIXTAXIICollector(BaseCollector):
    def __init__(self):
        self.feeds = [
            'https://otx.alienvault.com/api/v1/pulses/subscribed'
        ]

    def collect(self, query: str, limit: int = 100) -> List[Dict]:
        results = []
        try:
            for feed in self.feeds:
                response = requests.get(feed, timeout=10)
                response.raise_for_status()
                data = response.json()
                
                for item in data.get('results', [])[:limit//len(self.feeds)]:
                    if query.lower() in item.get('name', '').lower() or query.lower() in item.get('description', '').lower():
                        results.append({
                            'source': 'stix_taxii',
                            'name': item.get('name'),
                            'description': item.get('description'),
                            'created': item.get('created'),
                            'modified': item.get('modified'),
                            'url': item.get('references', [])[0] if item.get('references') else ''
                        })
            logger.info(f"Collected {len(results)} STIX/TAXII items for query: {query}")
        except requests.RequestException as e:
            logger.error(f"Error collecting data from STIX/TAXII feeds: {e}")
        return results
    
class ThreatDataCollector:
    def __init__(self):
        self.collectors = {
            'darkweb': DarkWebCollector(),
            'twitter': TwitterCollector(),
            'reddit': RedditCollector(),
            'blog': BlogCollector(),
            'stix': STIXTAXIICollector()
        }

    def collect_all(self, query: str, sources: List[str] = None, limit: int = 100) -> List[Dict]:
        if sources is None:
            sources = list(self.collectors.keys())

        all_data = []
        for source in sources:
            if source in self.collectors:
                logger.info(f"Collecting data from source: {source}")
                results = self.collectors[source].collect(query, limit)
                all_data.extend(results)
        logger.info(f"Total collected items for query '{query}': {len(all_data)}")
        return all_data
    
if __name__ == "__main__":
    collector = ThreatDataCollector()
    results = collector.collect_all(
        "ransomware", 
        sources=['twitter', 'reddit'], 
        limit=10
    )
    
    for result in results[:5]:  # Print first 5 results
        print(f"\nSource: {result['source']}")
        print(f"Text: {result.get('text', result.get('title', ''))[:200]}")