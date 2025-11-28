import re
from typing import List, Dict, Tuple
from transformers import AutoTokenizer
from loguru import logger

import config

class TextPreprocessor:
    def __init__(self, model_name: str = None):
        self.model_name = model_name or config.MODEL_NAME

        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            logger.info(f"Initialized TextProcessor with model: {self.model_name}")
        except Exception as e:
            logger.warning(f"Error loading tokenizer for model {self.model_name}: {e}")
            logger.error(f"Failing back to bert-base-uncased tokenizer.")
            self.tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")

    def clean_text(self, text: str) -> str:
        if not text:
            return ""

        cleaned_text = re.sub(r'<[^>]+>', '', text) # Remove HTML tags
        cleaned_text = re.sub(r'\s+', ' ', cleaned_text) # Remove extra whitespace
        cleaned_text = re.sub(r'[^\w\s\.\,\-\:\/@]', '', cleaned_text) # Remove special characters except some punctuation
        logger.debug("Cleaned text.")
        return cleaned_text.strip()

    def tokenize_text(self, text: str, max_length: int = None) -> Dict:
        max_length = max_length or config.MAX_LENGTH

        tokens = self.tokenizer(
            text, 
            add_special_tokens=True,
            padding="max_length",
            truncation=True,
            max_length=max_length,
            return_tensors="pt"
        )
        logger.debug(f"Tokenized text to {len(tokens)} tokens.")
        return tokens
    
    # Indicators of Compromise (IOCs) extraction
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        iocs = {
            'urls': re.findall(r'(https?://[^\s]+)', text),
            'emails': re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text),
            'ips': re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text),
            'hashes': re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b', text),
            'domains': re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)
        }

        for key in iocs:
            iocs[key] = list(set(iocs[key]))  # Remove duplicates

        logger.debug(f"Extracted IOCs: { {k: len(v) for k, v in iocs.items()} }")
        return iocs

    def extract_cves(self, text: str) -> List[str]:
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', text, re.IGNORECASE)
        unique_cves = list(set(cves))
        logger.debug(f"Extracted {len(unique_cves)} unique CVEs.")
        return unique_cves

    def preprocess_batch(self, texts: List[str]) -> Tuple[List[str], List[Dict]]:
        cleaned_texts = [self.clean_text(text) for text in texts]
        iocs_list = [self.extract_iocs(text) for text in cleaned_texts]
        tokenized_texts = [self.tokenize_text(text) for text in cleaned_texts]
        logger.info(f"Preprocessed batch of {len(texts)} texts.")
        return cleaned_texts, iocs_list, tokenized_texts

class DatasetBuilder:
    def __init__(self, preprocessor: TextPreprocessor):
        self.preprocessor = preprocessor

    def create_ner_dataset(self, labeled_data: List[Dict]) -> Dict:
        dataset = []
        for item in labeled_data:
            text = item['text']
            entities = item['entities']  # List of dicts with 'start', 'end', 'label'
            cleaned_text = self.preprocessor.clean_text(text)
            tokens = self.preprocessor.tokenize_text(cleaned_text)
            labels = self._align_labels_with_tokens(cleaned_text, entities, tokens)
            dataset.append({
                'input_ids': tokens['input_ids'],
                'attention_mask': tokens['attention_mask'],
                'labels': labels
            })
        logger.info(f"Created NER dataset with {len(dataset)} samples.")
        return dataset

    def _align_labels_with_tokens(self, text: str, entities: List[Dict], tokens: Dict) -> List[int]:
        labels = [0] * len(tokens['input_ids'][0])  # Initialize all to 'O' label (0)
        label_map = {label: idx for idx, label in enumerate(config.ENTITY_LABELS)}

        for entity in entities:
            start_char = entity['start']
            end_char = entity['end']
            label = entity['label'] 
            
            if f"B-{label}" not in label_map:
                logger.warning(f"Unknown label {label} found in entities.")
                continue
            else:
                b_label_id = label_map[f"B-{label}"]
                i_label_id = label_map.get(f"I-{label}", b_label_id)
            

        logger.debug("Aligned entity labels with tokens.")
        return labels

if __name__ == "__main__":
    preprocessor = TextPreprocessor()
    sample_text = """
    The APT group exploited CVE-2024-1234 to deploy ransomware.
    C2 server: 192.168.1.100
    Malicious URL: http://malicious-domain.com/payload.exe
    Hash: 5d41402abc4b2a76b9719d911017c592
    """

    cleaned = preprocessor.clean_text(sample_text)
    print("Cleaned Text:", cleaned)

    iocs = preprocessor.extract_iocs(cleaned)
    print("Extracted IOCs:", iocs)

    cves = preprocessor.extract_cves(cleaned)
    print("Extracted CVEs:", cves)