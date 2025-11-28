import torch

from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoTokenizer,
    AutoModelForTokenClassification,
    DataCollatorForTokenClassification,
    Trainer,
    TrainingArguments
)
from typing import List, Dict, Tuple
from loguru import logger
import config

class ThreatNERDataset(Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __len__(self):
        return len(self.encodings)

    def __getitem__(self, idx):
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.labels[idx])
        return item

class ThreatNERModel:
    def __init__(self, model_name: str = None, num_labels: int = None):
        self.model_name = model_name or config.MODEL_NAME
        self.num_labels = num_labels or len(config.ENTITY_LABELS)
        self.label2id = {label: i for i, label in enumerate(config.ENTITY_LABELS)}
        self.id2label = {i: label for label, i in self.label2id.items()}

        try:
            tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        except Exception as e:
            logger.warning(f"Error loading tokenizer for model {self.model_name}: {e}")
            logger.error(f"Failing back to bert-base-uncased tokenizer.")
            tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
        self.model = None

    def load_model(self, checkpoint_path: str = None):
        try:
            if checkpoint_path:
                self.model = AutoModelForTokenClassification.from_pretrained(
                    checkpoint_path,
                    num_labels=self.num_labels,
                    id2label=self.id2label,
                    label2id=self.label2id
                )
                logger.info(f"Loaded model from checkpoint: {checkpoint_path}")
            else:
                self.model = AutoModelForTokenClassification.from_pretrained(
                    self.model_name,
                    num_labels=self.num_labels,
                    id2label=self.id2label,
                    label2id=self.label2id
                )
                logger.info(f"Initialized model from pre-trained: {self.model_name}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise e

    def prepare_data(self, texts: List[str], labels: List[List[str]]) -> Dict:
        encodings = self.tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=config.MAX_LENGTH,
            return_tensors="pt"
        )

        if labels:
            encoded_labels = []
            for label_seq in labels:
                encoded_seq = [self.label2id.get(l, 0) for l in label_seq]
                # Pad or truncate to max_length
                encoded_seq = encoded_seq[:config.MAX_LENGTH] + [0] * (config.MAX_LENGTH - len(encoded_seq))
                encoded_labels.append(encoded_seq)
            return encodings, encoded_labels

        return encodings

    def train(self, train_texts: List[str], train_labels: List[List[str]], val_texts: List[str] = None,
              val_labels: List[List[str]] = None, output_dir: str = None):
        output_dir = output_dir or str(config.MODELS_DIR / 'threat_ner_model')

        train_encodings, train_labels_ids = self.prepare_data(train_texts, train_labels)
        train_dataset = ThreatNERDataset(train_encodings, train_labels_ids)

        val_dataset = None
        if val_texts and val_labels:
            val_encodings, val_labels_ids = self.prepare_data(val_texts, val_labels)
            val_dataset = ThreatNERDataset(val_encodings, val_labels_ids)

        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=config.NUM_EPOCHS,
            per_device_train_batch_size=config.BATCH_SIZE,
            per_device_eval_batch_size=config.BATCH_SIZE,
            learning_rate=config.LEARNING_RATE,
            weight_decay=0.01,
            evaluation_strategy="epoch" if val_dataset else "no",
            save_strategy="epoch",
            load_best_model_at_end=True if val_dataset else False,
            logging_dir=str(config.LOG_DIR / 'ner_training_logs'),
            logging_steps=10,
            save_total_limit=2
        )

        data_collator = DataCollatorForTokenClassification(self.tokenizer)

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            data_collator=data_collator
        )

        logger.info("Starting training...")
        trainer.train()

        self.model.save_pretrained(output_dir)
        self.tokenizer.save_pretrained(output_dir)
        logger.info(f"Model and tokenizer saved to {output_dir}")

    def predict(self, texts: List[str]) -> List[List[Tuple[str, str]]]:
        if not self.model:
            logger.error("Model not loaded. Call load_model() before prediction.")
            return []
        
        self.model.eval()
        encodings = self.prepare_data(texts)

        with torch.no_grad():
            outputs = self.model(**encodings)
            predictions = torch.argmax(outputs.logits, dim=2)

        results = []
        for i, text in enumerate(texts):
            tokens = self.tokenizer.tokenize(text)
            preds = [self.id2label[pred.item()] for pred in predictions[i][:len(tokens)]]

            entities = list(zip(tokens, preds))
            results.append(entities)

        return results

    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        predictions = self.predict([text])[0]
        
        entities = {
            'IOC': [],
            'MALWARE': [],
            'CVE': [],
            'ACTOR': [],
            'TTP': []
        }

        current_entity = []
        current_type = None

        for token, label in predictions:
            if label.startswith("B-"):
                if current_entity and current_type:
                    entity_text = " ".join(current_entity).replace("##", "")
                    entities[current_type].append(entity_text)

                current_entity = [token]
                current_type = label.split('-')[1]
            elif label.startswith("I-") and current_type:
                current_entity.append(token)
            else:
                if current_entity and current_type:
                    entity_text = " ".join(current_entity).replace("##", "")
                    entities[current_type].append(entity_text)
                current_entity = []
                current_type = None

        if current_entity and current_type:
            entity_text = " ".join(current_entity).replace("##", "")
            entities.setdefault(current_type, []).append(entity_text)

        return entities

if __name__ == "__main__":
    # Example usage
    model = ThreatNERModel()
    model.load_model()
    
    # Example training data (you need real labeled data)
    train_texts = [
        "APT29 used Cobalt Strike to exploit CVE-2024-1234",
        "Ransomware group deployed malware via phishing",
    ]
    
    train_labels = [
        ["B-ACTOR", "O", "B-MALWARE", "I-MALWARE", "O", "O", "B-CVE"],
        ["B-MALWARE", "O", "O", "B-MALWARE", "O", "O"],
    ]
    
    # Note: This is simplified. Real training needs proper data preparation
    logger.info("NER model initialized. Ready for training with real data.")