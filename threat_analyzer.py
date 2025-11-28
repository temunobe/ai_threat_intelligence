"""
Threat analysis including sentiment analysis, clustering, and anomaly detection
"""
import numpy as np
from typing import List, Dict
from sklearn.cluster import DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from transformers import pipeline
from loguru import logger
import config


class ThreatSentimentAnalyzer:
    """Analyze urgency and sentiment of threat data"""
    
    def __init__(self):
        try:
            self.sentiment_pipeline = pipeline(
                "sentiment-analysis",
                model="distilbert-base-uncased-finetuned-sst-2-english"
            )
        except Exception as e:
            logger.warning(f"Could not load sentiment model: {e}")
            self.sentiment_pipeline = None
        
        self.urgency_keywords = config.URGENCY_KEYWORDS
    
    def analyze_urgency(self, text: str) -> Dict:
        """Detect urgency and malicious intent"""
        text_lower = text.lower()
        
        # Count urgency keywords
        urgency_score = sum(1 for keyword in self.urgency_keywords 
                          if keyword in text_lower)
        
        # Normalize score (0-10 scale)
        max_score = 5  # Normalize to reasonable max
        urgency_score = min(urgency_score, max_score) / max_score * 10
        
        # Get sentiment if available
        sentiment = {'label': 'UNKNOWN', 'score': 0.0}
        if self.sentiment_pipeline:
            try:
                # Truncate long texts
                truncated_text = text[:512]
                result = self.sentiment_pipeline(truncated_text)[0]
                sentiment = result
            except Exception as e:
                logger.warning(f"Sentiment analysis failed: {e}")
        
        # Determine threat level
        if urgency_score >= 7:
            threat_level = 'CRITICAL'
        elif urgency_score >= 5:
            threat_level = 'HIGH'
        elif urgency_score >= 3:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'
        
        return {
            'urgency_score': float(urgency_score),
            'threat_level': threat_level,
            'sentiment': sentiment['label'],
            'sentiment_confidence': sentiment['score'],
            'keywords_found': [kw for kw in self.urgency_keywords if kw in text_lower]
        }
    
    def analyze_batch(self, texts: List[str]) -> List[Dict]:
        """Analyze a batch of texts"""
        results = []
        for text in texts:
            results.append(self.analyze_urgency(text))
        return results


class ThreatClusterer:
    """Cluster similar threats together"""
    
    def __init__(self, eps: float = None, min_samples: int = None):
        self.eps = eps or config.DBSCAN_EPS
        self.min_samples = min_samples or config.DBSCAN_MIN_SAMPLES
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.clustering_model = None
    
    def cluster_threats(self, threat_texts: List[str]) -> Dict:
        """Cluster threats using DBSCAN"""
        if len(threat_texts) < self.min_samples:
            logger.warning(f"Not enough samples for clustering (need at least {self.min_samples})")
            return {
                'labels': [0] * len(threat_texts),
                'n_clusters': 0,
                'n_noise': len(threat_texts)
            }
        
        # Vectorize texts
        try:
            X = self.vectorizer.fit_transform(threat_texts)
        except Exception as e:
            logger.error(f"Vectorization failed: {e}")
            return {
                'labels': [0] * len(threat_texts),
                'n_clusters': 0,
                'n_noise': len(threat_texts)
            }
        
        # Cluster
        self.clustering_model = DBSCAN(eps=self.eps, min_samples=self.min_samples)
        labels = self.clustering_model.fit_predict(X)
        
        # Analyze results
        n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
        n_noise = list(labels).count(-1)
        
        logger.info(f"Found {n_clusters} clusters with {n_noise} noise points")
        
        return {
            'labels': labels.tolist(),
            'n_clusters': n_clusters,
            'n_noise': n_noise,
            'cluster_sizes': self._get_cluster_sizes(labels)
        }
    
    def _get_cluster_sizes(self, labels: np.ndarray) -> Dict:
        """Get size of each cluster"""
        unique, counts = np.unique(labels, return_counts=True)
        return {int(label): int(count) for label, count in zip(unique, counts) if label != -1}
    
    def get_cluster_representatives(self, threat_texts: List[str], 
                                   labels: List[int]) -> Dict[int, str]:
        """Get representative text for each cluster"""
        representatives = {}
        
        for cluster_id in set(labels):
            if cluster_id == -1:  # Skip noise
                continue
            
            # Get texts in this cluster
            cluster_texts = [text for text, label in zip(threat_texts, labels) 
                           if label == cluster_id]
            
            # Use the longest text as representative (or implement better selection)
            representatives[cluster_id] = max(cluster_texts, key=len)
        
        return representatives


class AnomalyDetector:
    """Detect anomalous threats"""
    
    def __init__(self, contamination: float = None):
        self.contamination = contamination or config.ANOMALY_CONTAMINATION
        self.vectorizer = TfidfVectorizer(max_features=500, stop_words='english')
        self.model = IsolationForest(contamination=self.contamination, random_state=42)
    
    def detect_anomalies(self, threat_texts: List[str]) -> Dict:
        """Detect anomalous threats"""
        if len(threat_texts) < 10:
            logger.warning("Not enough samples for anomaly detection (need at least 10)")
            return {
                'predictions': [1] * len(threat_texts),
                'n_anomalies': 0,
                'anomaly_indices': []
            }
        
        # Vectorize
        try:
            X = self.vectorizer.fit_transform(threat_texts)
        except Exception as e:
            logger.error(f"Vectorization failed: {e}")
            return {
                'predictions': [1] * len(threat_texts),
                'n_anomalies': 0,
                'anomaly_indices': []
            }
        
        # Detect anomalies
        predictions = self.model.fit_predict(X)
        
        # -1 indicates anomaly, 1 indicates normal
        anomaly_indices = [i for i, pred in enumerate(predictions) if pred == -1]
        n_anomalies = len(anomaly_indices)
        
        logger.info(f"Detected {n_anomalies} anomalies out of {len(threat_texts)} samples")
        
        return {
            'predictions': predictions.tolist(),
            'n_anomalies': n_anomalies,
            'anomaly_indices': anomaly_indices,
            'anomaly_texts': [threat_texts[i] for i in anomaly_indices]
        }
    
    def get_anomaly_scores(self, threat_texts: List[str]) -> List[float]:
        """Get anomaly scores for each sample"""
        if len(threat_texts) < 10:
            return [0.0] * len(threat_texts)
        
        X = self.vectorizer.transform(threat_texts)
        scores = self.model.decision_function(X)
        
        # Normalize scores to 0-1 range (lower score = more anomalous)
        min_score, max_score = scores.min(), scores.max()
        if max_score - min_score > 0:
            normalized_scores = (scores - min_score) / (max_score - min_score)
        else:
            normalized_scores = np.ones_like(scores) * 0.5
        
        return normalized_scores.tolist()


class ThreatAnalyzer:
    """Main threat analysis orchestrator"""
    
    def __init__(self):
        self.sentiment_analyzer = ThreatSentimentAnalyzer()
        self.clusterer = ThreatClusterer()
        self.anomaly_detector = AnomalyDetector()
    
    def analyze_threat(self, text: str, entities: Dict = None) -> Dict:
        """Comprehensive analysis of a single threat"""
        analysis = {
            'sentiment': self.sentiment_analyzer.analyze_urgency(text),
            'entities': entities or {}
        }
        
        return analysis
    
    def analyze_batch(self, threat_data: List[Dict]) -> Dict:
        """Analyze a batch of threats"""
        texts = [item['text'] for item in threat_data]
        
        # Sentiment analysis
        logger.info("Running sentiment analysis...")
        sentiment_results = self.sentiment_analyzer.analyze_batch(texts)
        
        # Clustering
        logger.info("Running threat clustering...")
        clustering_results = self.clusterer.cluster_threats(texts)
        
        # Anomaly detection
        logger.info("Running anomaly detection...")
        anomaly_results = self.anomaly_detector.detect_anomalies(texts)
        
        # Combine results
        for i, item in enumerate(threat_data):
            item['sentiment'] = sentiment_results[i]
            item['cluster'] = int(clustering_results['labels'][i])
            item['is_anomaly'] = anomaly_results['predictions'][i] == -1
        
        return {
            'analyzed_threats': threat_data,
            'clustering': clustering_results,
            'anomalies': anomaly_results,
            'summary': {
                'total_threats': len(threat_data),
                'n_clusters': clustering_results['n_clusters'],
                'n_anomalies': anomaly_results['n_anomalies'],
                'critical_threats': sum(1 for s in sentiment_results 
                                      if s['threat_level'] == 'CRITICAL'),
                'high_threats': sum(1 for s in sentiment_results 
                                  if s['threat_level'] == 'HIGH')
            }
        }


if __name__ == "__main__":
    # Test threat analyzer
    analyzer = ThreatAnalyzer()
    
    sample_threats = [
        {
            'text': 'Critical zero-day vulnerability exploited by ransomware group',
            'source': 'twitter'
        },
        {
            'text': 'New malware campaign targets financial institutions',
            'source': 'blog'
        },
        {
            'text': 'APT group uses sophisticated techniques for data exfiltration',
            'source': 'reddit'
        },
        {
            'text': 'Security update released for common software',
            'source': 'blog'
        }
    ]
    
    results = analyzer.analyze_batch(sample_threats)
    
    print(f"\nAnalysis Summary:")
    print(f"  Total threats: {results['summary']['total_threats']}")
    print(f"  Clusters: {results['summary']['n_clusters']}")
    print(f"  Anomalies: {results['summary']['n_anomalies']}")
    print(f"  Critical: {results['summary']['critical_threats']}")
    print(f"  High: {results['summary']['high_threats']}")
    
    print(f"\nThreat Details:")
    for threat in results['analyzed_threats']:
        print(f"\n  Text: {threat['text'][:60]}...")
        print(f"  Level: {threat['sentiment']['threat_level']}")
        print(f"  Cluster: {threat['cluster']}")
        print(f"  Anomaly: {threat['is_anomaly']}")