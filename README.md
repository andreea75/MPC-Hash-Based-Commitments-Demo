# MPC with Commitments - Python Implementation

## Setup Instructions

### 1. Environment Setup
```bash
# Create virtual environment (recommended)
python -m venv mpc_env
source mpc_env/bin/activate  # On Windows: mpc_env\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Dependencies
Create `requirements.txt` with:
```
matplotlib>=3.5.0
numpy>=1.21.0
```

### 3. Run the Complete Demo
```bash
python main.py
```

## Implementation Overview

### Basic MPC Protocol
- **Goal**: Implement 2-party secret sharing without security
- **Features**: 
  - Additive secret sharing (x = x1 + x2)
  - Basic sum and product computation
  - Performance baseline measurement

### Commitment Schemes
- **Goal**: Add cryptographic commitments for security
- **Features**:
  - SHA-3 based commitments: `commit = SHA3-256(value || nonce)`
  - Cheating detection and prevention
  - Secure reveal and verify phases

### Post-Quantum Security
- **Goal**: Analyze and benchmark post-quantum properties
- **Features**:
  - SHA-3 justification for post-quantum security
  - Performance benchmarking (10+ runs)
  - Overhead analysis and visualization
