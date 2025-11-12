# AI Agent Instructions for File Format Analysis Project

This project implements a file format analyzer that extracts features from different file types using sniffers and parsers, with additional tools for entropy analysis and security testing.

## Project Architecture

### Key Components

1. **Orchestrator (`extract.py`)**
   - Main entry point that coordinates:
     - Directory traversal
     - File type detection via sniffer
     - Feature extraction via format-specific parsers
     - Feature output in JSON format

2. **Sniffer (`featurizers/sniff.py`)**
   - Identifies file types by magic numbers/signatures
   - Routes files to appropriate format parsers
   - Returns basic file metadata

3. **Format Parsers (`featurizers/parsers/`)**
   - Format-specific feature extractors:
   - Current implementations: gzip, jpeg, mp4, ole2, ooxml, pdf, png, rar, zip
   - Each parser extracts format-specific structural features

4. **Parser Registry (`featurizers/parser_registry.py`)**
   - Automatic parser discovery system
   - Convention-based registration:
     - Searches `parsers/` directory
     - Registers functions named `parse_*` or `parse` in `*_feat.py` files
     - Maps format families to parser functions
   - No hardcoded paths - works with any PYTHONPATH

5. **Feature Aggregator (`featurizers/features_a.py`)**
   - Combines and normalizes features from multiple sources:
     - Common sniffer features (size, magic, format family)
     - Format-specific parser features
     - NULL handling for missing features
   - Ensures consistent feature set across all files
   - Implements class A feature aggregation logic

6. **Configuration (`config/features.yaml`)**
   - Controls enabled parsers and feature definitions
   - Defines global settings:
     ```yaml
     global:
       read:
         head_bytes: 16384    # Header read size
         tail_bytes: 16384    # Trailer read size
       size_filters:
         min_bytes: 1024      # Minimum file size
       sniffer:
         enabled_families: [...] # Active parsers
     ```
   - Specifies feature schema:
     ```yaml
     features:
       common:     # Global features
         - name: size_bytes
           type: int
       gzip:       # Format-specific features
         - name: gzip_header_ok
           type: bool
     ```
   - Defines imputation rules for missing values

### Data Flow

```
                     ┌─── Parser Registry ───┐
                     │                      │
                     ▼                      ▼
Input File → Sniffer → Format Parser → Feature Aggregator → Output
                ▲          ▲            ▲
                └──────────┴────────────┘
                     Config File
```

### Feature Processing Pipeline

1. **File Detection**
   - Sniffer checks magic numbers/signatures
   - Determines format family
   - Extracts basic metadata

2. **Parser Selection**
   - Registry looks up parser for detected format
   - Validates parser availability
   - Handles format-specific parsing

3. **Feature Aggregation**
   - Combines sniffer and parser features
   - Ensures all configured features exist
   - Applies type conversion and NULL handling
   - Produces consistent feature dictionary

## Development Patterns

1. **File Format Parser Pattern**
   ```python
   def parse_format_features(path: str) -> dict:
       # Basic error handling - return None or default features on failure
       try:
           # Extract format-specific features
           return {
               "feature_name": value,
               # ... more features
           }
       except Exception:
           # Minimalist error handling - silently skip problematic files
           return None
   ```

2. **Feature Extraction Pattern**
   - Boolean features for structural validity checks
   - Integer features for countable properties
   - Float features for ratios/fractions
   - Enum/string features for categorization

3. **Error Handling**
   - Minimalist approach: skip problematic files with basic error reporting
   - Each parser handles its own format-specific errors

## Key Functions

1. **File Type Detection**
   ```python
   # In sniff.py
   def sniff(path: str, cfg: dict) -> dict:
       """
       Returns: dict(
           format_family,     # Detected format for parser routing
           magic_ok,         # Known format signature found
           magic_family,     # Broader format classification
           size_bytes,       # File size
           fallback_max_attempts  # From config
       )
       """
   ```

2. **Feature Extraction**
   ```python
   # In extract.py
   def extract_one(file_path: str, cfg: dict) -> dict:
       """
       Returns combined features from:
       - Basic file metadata
       - Sniffer results
       - Format-specific parser features
       """
   ```

## Common Operations

1. Reading Files:
   - Use `read_bytes()` for raw binary access
   - Config defines `head_bytes`/`tail_bytes` buffer sizes
   - Handle large files efficiently with chunked reading

2. Adding New Parsers:
   - Create new parser in `featurizers/parsers/`
   - Add format to `enabled_families` in config
   - Register parser in `PARSERS` dict in `extract.py`

## Config Conventions

1. Feature Naming:
   - Format-specific prefix (e.g., `gzip_`, `pdf_`)
   - Boolean features end with descriptive state
   - Count features end with `_count`
   - Fraction features end with `_fraction`

2. Default Values:
   - Boolean: `False`
   - Integer: `0`
   - Float: `0.0`

## Additional Tools

The `additional_data/` directory contains advanced analysis and security testing tools:

### Entropy Analysis Tools
1. `sliding_entropy.py`
   - Calculates sliding window entropy analysis
   - Uses 256-byte windows
   - Compares original file vs AES-encrypted version
   - Generates visualization plots

2. `one_file_entropy.py`
   - Single file entropy analysis
   - Calculates Shannon entropy before/after encryption
   - Quick entropy assessment tool

3. `file_entropy.py`
   - Batch entropy analysis for multiple files
   - Calculates average entropy across file sets
   - Useful for format-specific entropy profiling

4. `byte_frequency.py`
   - Analyzes byte value distribution
   - Compares original vs encrypted data
   - Visualizes frequency patterns with matplotlib

### Security Testing Tools
1. `AES_Cipher.py`
   - Implements AES-256-CBC encryption
   - Uses PKCS7 padding
   - Generates secure random keys and IVs
   - Creates separate key files for testing
   - Features:
     ```python
     - 32-byte keys (AES-256)
     - 16-byte IV for CBC mode
     - Preserves original filenames
     - Timestamp-based key file naming
     ```

### Usage Patterns

1. Entropy Analysis:
   ```python
   # Single file analysis
   python one_file_entropy.py
   # Input: file path
   # Output: entropy before/after encryption

   # Sliding window analysis
   python sliding_entropy.py
   # Input: file path
   # Output: entropy plot visualization
   ```

2. Encryption Testing:
   ```python
   python AES_Cipher.py
   # Input: source file, output directory
   # Output: encrypted file + separate key file
   ```

These tools are essential for:
- Format-specific entropy profiling
- Security testing of parsers
- Validation of encryption detection
- Performance testing with large files