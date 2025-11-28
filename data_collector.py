# data_collector.py
# Module for collecting data from various sources
import requests
import praw
import tweepy
import time
import shelve
import hashlib
import json
import os
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
        # Prefer using Tweepy v2 Client if a bearer token is provided
        self.client_v2 = None
        self.client = None
        # Cache path for Twitter v2 query caching
        self._cache_path = os.path.join(str(config.CACHE_DIR), 'twitter_cache.db')

        if config.TWITTER_BEARER_TOKEN:
            try:
                self.client_v2 = tweepy.Client(bearer_token=config.TWITTER_BEARER_TOKEN)
                logger.info("Initialized Twitter v2 client (Client) using bearer token.")
                # don't return here so v1.1 fallback remains available on initialization errors
            except Exception as e:
                logger.warning(f"Failed to initialize Twitter v2 client: {e}")

        # Fallback to v1.1 API using OAuth1 if all required keys are present
        if not all([config.TWITTER_API_KEY, config.TWITTER_API_SECRET,
                    config.TWITTER_ACCESS_TOKEN, config.TWITTER_ACCESS_SECRET]):
            logger.warning("Twitter API credentials are not configured for v1.1 usage.")
            return

            try:
                auth = tweepy.OAuth1UserHandler(
                    config.TWITTER_API_KEY,
                    config.TWITTER_API_SECRET
                )
                auth.set_access_token(
                    config.TWITTER_ACCESS_TOKEN,
                    config.TWITTER_ACCESS_SECRET
                )
                self.client = tweepy.API(auth)
                logger.info("Initialized Twitter v1.1 API client (tweepy.API) using OAuth1.")
            except Exception as e:
                logger.error(f"Failed to initialize Twitter v1.1 client: {e}")

    # --- Simple on-disk cache helpers for v2 queries ---
    def _cache_key(self, query: str, limit: int) -> str:
        h = hashlib.sha256()
        h.update(f"{query}\n{limit}".encode('utf-8'))
        return h.hexdigest()

    def _cache_get(self, key: str):
        try:
            with shelve.open(self._cache_path) as db:
                item = db.get(key)
                if not item:
                    return None
                payload = json.loads(item)
                if time.time() - payload.get('ts', 0) > config.TWITTER_CACHE_TTL:
                    # expired
                    try:
                        del db[key]
                    except Exception:
                        pass
                    return None
                return payload.get('data')
        except Exception:
            return None

    def _cache_set(self, key: str, data):
        try:
            with shelve.open(self._cache_path) as db:
                db[key] = json.dumps({'ts': time.time(), 'data': data})
        except Exception:
            pass

    def collect(self, query: str, limit: int = 100) -> List[Dict]:
        results = []

        # If v2 client exists, use recent search v2 endpoint
        if self.client_v2:
                # Check simple on-disk cache first
                cache_key = self._cache_key(query, limit)
                cached = self._cache_get(cache_key)
                if cached is not None:
                    logger.info(f"Returning {len(cached)} cached tweets (v2) for query: {query}")
                    return cached

                # Retry loop to handle rate limiting (429 Too Many Requests)
                max_retries = getattr(config, 'TWITTER_V2_MAX_RETRIES', 3)
                backoff_base = getattr(config, 'TWITTER_V2_BACKOFF_BASE', 2)
                resp = None
                for attempt in range(max_retries):
                    try:
                        # Request tweet text and author username via expansions
                        resp = self.client_v2.search_recent_tweets(query=query, max_results=min(100, limit), tweet_fields=['created_at'], expansions=['author_id'], user_fields=['username'])
                        break
                    except Exception as e:
                        try:
                            from tweepy.errors import TooManyRequests, Forbidden, TweepyException
                            # If the exception includes a response with rate limit headers, prefer sleeping until reset
                            resp_obj = getattr(e, 'response', None)
                            headers = getattr(resp_obj, 'headers', {}) if resp_obj is not None else {}
                            if isinstance(e, TooManyRequests):
                                # Prefer reset header if present
                                reset = headers.get('x-rate-limit-reset') or headers.get('x-rate_limit_reset')
                                retry_after = headers.get('retry-after')
                                if reset:
                                    try:
                                        reset_ts = int(reset)
                                        sleep_for = max(0, reset_ts - int(time.time()) + 5)
                                    except Exception:
                                        sleep_for = backoff_base ** attempt
                                elif retry_after:
                                    try:
                                        sleep_for = int(retry_after)
                                    except Exception:
                                        sleep_for = backoff_base ** attempt
                                else:
                                    sleep_for = backoff_base ** attempt

                                if sleep_for > 0 and attempt < max_retries - 1:
                                    logger.warning(f"Twitter v2 rate limit hit (429). Sleeping {sleep_for}s before retry {attempt+1}/{max_retries}.")
                                    time.sleep(min(sleep_for, 3600))
                                    continue
                                else:
                                    logger.error("Twitter v2 API rate limit exceeded after retries.")
                                    return results
                            elif isinstance(e, Forbidden):
                                logger.error("Twitter v2 API returned Forbidden (403): check your app permissions or access level for v2 endpoints.")
                                return results
                            elif isinstance(e, TweepyException):
                                logger.error(f"Twitter v2 API error: {e}")
                                return results
                            else:
                                logger.error(f"Unexpected error collecting data from Twitter v2: {e}")
                                return results
                        except Exception:
                            logger.error(f"Unexpected error collecting data from Twitter v2: {e}")
                            return results

                if not resp:
                    logger.error("No response from Twitter v2 after retries.")
                    return results

                tweets = resp.data or []
                users = {str(u.id): u for u in (resp.includes.get('users', []) if resp.includes else [])}

                for t in tweets:
                    author = users.get(str(t.author_id)) if users else None
                    username = author.username if author and hasattr(author, 'username') else str(t.author_id)
                    results.append({
                        'source': 'twitter',
                        'text': t.text,
                        'author': username,
                        'timestamp': t.created_at.isoformat() if t.created_at else None,
                        'url': f"https://twitter.com/{username}/status/{t.id}"
                    })

                logger.info(f"Collected {len(results)} tweets (v2) for query: {query}")
                # Cache the results
                try:
                    self._cache_set(cache_key, results)
                except Exception:
                    pass

        # Fall back to v1.1 API
        if not self.client:
            logger.warning("Twitter client is not initialized due to missing credentials.")
            return []

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
        except Exception as e:
            # Modern tweepy raises exceptions under tweepy.errors (TweepyException and subclasses)
            try:
                from tweepy.errors import TweepyException, Forbidden
                if isinstance(e, Forbidden):
                    # 403 Forbidden typically means your app credentials are valid but your access
                    # level doesn't allow use of this v1.1 endpoint (search_tweets).
                    logger.error("Twitter API returned 403 Forbidden: your developer account may have limited access to this v1.1 endpoint. See https://developer.x.com/en/portal/product")
                elif isinstance(e, TweepyException):
                    logger.error(f"Twitter API error: {e}")
                else:
                    logger.error(f"Unexpected error collecting data from Twitter: {e}")
            except Exception:
                # If tweepy import or checks fail for some reason, log the raw exception
                logger.error(f"Unexpected error collecting data from Twitter: {e}")
        return results
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