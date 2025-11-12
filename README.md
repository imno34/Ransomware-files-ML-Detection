# File Format Analyzer

A Python-based tool for analyzing and extracting features from different file formats. This project implements file format analyzers that extract features from various file types using sniffers and parsers, with additional tools for entropy analysis and security testing.

## Project Structure

- `extract.py` - Main entry point that coordinates directory traversal, file type detection, and feature extraction
- `featurizers/` - Core feature extraction modules
  - `sniff.py` - File type detection via magic numbers/signatures
  - `features_a.py` - Feature aggregation and normalization
  - `parser_registry.py` - Automatic parser discovery system
  - `parsers/` - Format-specific feature extractors
    - Supported formats: gzip, jpeg, mp4, ole2, ooxml, pdf, png, rar, zip
- `config/` - Configuration files
  - `features.yaml` - Controls enabled parsers and feature definitions
- `additional_data/` - Advanced analysis tools
  - `sliding_entropy.py` - Sliding window entropy analysis
  - `file_entropy.py` - Batch entropy analysis
  - `byte_frequency.py` - Byte value distribution analysis
  - `AES_Cipher.py` - AES-256-CBC encryption implementation

## Features

- File type detection using magic numbers/signatures
- Format-specific feature extraction
- Entropy analysis tools
- Security testing capabilities
- Automatic parser discovery
- Configurable feature extraction
- AES-256-CBC encryption support

## Configuration

The `config/features.yaml` file controls:
- Enabled parsers
- Feature definitions
- Global settings (buffer sizes, filters)
- Feature schema
- Imputation rules for missing values

## Usage

Basic feature extraction:
```python
python extract.py [input_file_or_directory] [output_file]
```

For additional tools like entropy analysis:
```python
python additional_data/sliding_entropy.py [input_file]
python additional_data/file_entropy.py [input_directory]
```

## License

[Add your chosen license here]