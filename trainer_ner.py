"""
Script to train the NER model
"""
import sys
import json
from pathlib import Path
from loguru import logger

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ner_model import ThreatNERModel
from text_preprocessor import DatasetBuilder, TextPreprocessor
import config


def load_labeled_data(data_path: str):
    """
    Load labeled data from JSON file
    Expected format:
    [
        {
            "text": "APT29 used Cobalt Strike to exploit CVE-2024-1234",
            "entities": [
                {"start": 0, "end": 5, "label": "ACTOR"},
                {"start": 11, "end": 24, "label": "MALWARE"},
                {"start": 36, "end": 50, "label": "CVE"}
            ]
        },
        ...
    ]
    """
    with open(data_path, 'r') as f:
        return json.load(f)


def prepare_ner_data(labeled_data):
    """Convert labeled data to training format"""
    texts = []
    labels = []
    
    for item in labeled_data:
        text = item['text']
        texts.append(text)
        
        # Create label sequence (simplified - needs proper alignment)
        # In production, implement proper BIO tagging
        label_seq = ['O'] * len(text.split())
        
        # This is simplified - implement proper token-level labeling
        for entity in item['entities']:
            label = entity['label']
            # Map to BIO tags
            if label in ['ACTOR', 'MALWARE', 'CVE', 'IOC', 'TTP']:
                # This is a placeholder - implement proper alignment
                pass
        
        labels.append(label_seq)
    
    return texts, labels


def create_sample_training_data():
    """Create sample training data for demonstration"""
    sample_data = [
        {
            "text": "APT29 uses Cobalt Strike malware to exploit CVE-2024-1234",
            "entities": [
                {"start": 0, "end": 5, "label": "ACTOR"},
                {"start": 11, "end": 24, "label": "MALWARE"},
                {"start": 44, "end": 58, "label": "CVE"}
            ]
        },
        {
            "text": "The ransomware group distributed the payload via phishing emails",
            "entities": [
                {"start": 4, "end": 14, "label": "MALWARE"}
            ]
        },
        {
            "text": "Threat actor deployed backdoor on server 192.168.1.100",
            "entities": [
                {"start": 42, "end": 55, "label": "IOC"}
            ]
        },
        {
            "text": "Lazarus Group exploits zero-day vulnerability in software",
            "entities": [
                {"start": 0, "end": 13, "label": "ACTOR"}
            ]
        },
        {
            "text": "The malware communicates with C2 server at malicious-domain.com",
            "entities": [
                {"start": 47, "end": 64, "label": "IOC"}
            ]
        }
    ]
    
    # Save sample data
    sample_path = config.DATA_DIR / "sample_training_data.json"
    with open(sample_path, 'w') as f:
        json.dump(sample_data, f, indent=2)
    
    logger.info(f"Created sample training data at {sample_path}")
    return sample_data


def train_model(train_data_path: str = None, val_data_path: str = None):
    """Train the NER model"""
    
    logger.info("Starting NER model training...")
    
    # Load or create training data
    if train_data_path and Path(train_data_path).exists():
        train_data = load_labeled_data(train_data_path)
    else:
        logger.warning("No training data provided, creating sample data...")
        train_data = create_sample_training_data()
    
    # Load validation data if available
    val_data = None
    if val_data_path and Path(val_data_path).exists():
        val_data = load_labeled_data(val_data_path)
    
    # Prepare data
    train_texts, train_labels = prepare_ner_data(train_data)
    
    val_texts, val_labels = None, None
    if val_data:
        val_texts, val_labels = prepare_ner_data(val_data)
    
    # Initialize model
    logger.info("Initializing NER model...")
    model = ThreatNERModel()
    model.load_model()  # Load base model
    
    # Train
    logger.info("Training model...")
    logger.warning(
        "Note: This is a simplified training example. "
        "In production, you need properly labeled data with BIO tags."
    )
    
    try:
        model.train(
            train_texts=train_texts,
            train_labels=train_labels,
            val_texts=val_texts,
            val_labels=val_labels
        )
        
        logger.info("✅ Model training completed!")
        logger.info(f"Model saved to {config.MODELS_DIR / 'threat-ner'}")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        logger.info("This is expected with sample data. Use real labeled data for training.")
        return False
    
    return True


def test_model():
    """Test the trained model"""
    logger.info("Testing trained model...")
    
    # Load model
    model = ThreatNERModel()
    model_path = config.MODELS_DIR / "threat-ner"
    
    if not model_path.exists():
        logger.error("No trained model found. Train the model first.")
        return
    
    model.load_model(str(model_path))
    
    # Test samples
    test_samples = [
        "APT29 deployed Cobalt Strike to exploit CVE-2024-5678",
        "The ransomware encrypted files and demanded payment in Bitcoin",
        "Malicious IP address 203.0.113.42 was used for C2 communication"
    ]
    
    logger.info("\nTest Results:")
    for text in test_samples:
        entities = model.extract_entities(text)
        logger.info(f"\nText: {text}")
        logger.info(f"Entities: {entities}")


def main():
    """Main training script"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Train NER model for threat intelligence")
    parser.add_argument("--train", type=str, help="Path to training data JSON")
    parser.add_argument("--val", type=str, help="Path to validation data JSON")
    parser.add_argument("--test", action="store_true", help="Test the trained model")
    
    args = parser.parse_args()
    
    if args.test:
        test_model()
    else:
        train_model(args.train, args.val)


if __name__ == "__main__":
    # Configure logging
    logger.add(
        config.LOGS_DIR / "training.log",
        rotation="100 MB",
        level=config.LOG_LEVEL
    )
    
    main()