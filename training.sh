#!/bin/bash

# Exit on error
set -e

# Output log
exec > >(tee -a training_log.log) 2>&1

# Setup script for AI-Driven Threat Intelligence Platform

echo "=========================================="
echo "AI-Driven Threat Intelligence Platform"
echo "Setup Script"
echo "=========================================="
echo ""

# Check GPU availability
if ! command -v nvidia-smi &> /dev/null; then
    echo "ERROR: nvidia-smi not found. CUDA not available?"
    exit 1
fi

GPU_COUNT=$(nvidia-smi --list-gpus | wc -l)
echo "Detected $GPU_COUNT GPUs"
nvidia-smi --query-gpu=index,name,memory.total --format=csv

# Set environment variables for better memory management
export PYTORCH_ALLOC_CONF="expandable_segments:True"
export TOKENIZERS_PARALLELISM=true

echo ""
echo "=========================================="
echo "Starting Training (Single Process Mode)"
echo "Model will automatically shard across all GPUs"
echo "=========================================="
echo ""

# Download spaCy model
# echo ""
# echo "Downloading spaCy language model..."
# python -m spacy download en_core_web_sm

# Run as single process - device_map="auto" handles multi-GPU
source ./aifinalenv/bin/activate
python run.py --query ransomware --sources twitter,reddit --limit 50 --output outputs/results.json
#accelerate launch --multi_gpu --num_processes 2 iomt_policy_generation.py

echo ""
echo "=========================================="
echo "Training Complete!"
echo "=========================================="