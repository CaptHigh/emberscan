# Contributing to EmberScan

Thank you for your interest in contributing to EmberScan! This document provides guidelines and information for contributors.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Please:

- Be respectful and inclusive in your language
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

### Prerequisites

- Python 3.9 or higher
- Git
- Linux environment (Ubuntu/Debian recommended)
- Basic understanding of embedded systems and security

### First-Time Setup

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/emberscan.git
   cd emberscan
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/emberscan/emberscan.git
   ```

4. **Install development dependencies**:
   ```bash
   # Create virtual environment
   python -m venv venv
   source venv/bin/activate
   
   # Install in development mode
   pip install -e ".[dev]"
   
   # Install pre-commit hooks
   pre-commit install
   ```

5. **Install system dependencies**:
   ```bash
   sudo apt install binwalk squashfs-tools qemu-system-mips nmap
   ```

## Development Setup

### Project Structure

```
emberscan/
├── emberscan/           # Main package
│   ├── core/            # Core functionality
│   ├── extractors/      # Firmware extraction
│   ├── emulators/       # QEMU management
│   ├── scanners/        # Vulnerability scanners
│   ├── reporters/       # Report generation
│   ├── utils/           # Utility functions
│   └── plugins/         # Plugin system
├── tests/               # Test suite
├── docs/                # Documentation
├── configs/             # Configuration files
├── scripts/             # Utility scripts
└── docker/              # Docker files
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=emberscan --cov-report=html

# Run specific test file
pytest tests/test_scanner.py -v

# Run tests matching pattern
pytest -k "test_extract" -v
```

### Code Quality Tools

```bash
# Format code
black emberscan tests
isort emberscan tests

# Lint
flake8 emberscan tests
mypy emberscan
```

## Making Changes

### Branch Naming

Use descriptive branch names:

- `feature/add-new-scanner` - New features
- `fix/crash-on-extract` - Bug fixes
- `docs/update-readme` - Documentation
- `refactor/scanner-base` - Code refactoring

### Workflow

1. **Sync with upstream**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Create feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make changes** and commit frequently

4. **Run tests** before submitting:
   ```bash
   pytest
   black --check emberscan tests
   flake8 emberscan tests
   ```

## Submitting Changes

### Pull Request Process

1. **Update your branch**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

3. **Create Pull Request** on GitHub with:
   - Clear title describing the change
   - Description of what and why
   - Reference to related issues
   - Screenshots if UI changes

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added/updated for changes
- [ ] Documentation updated if needed
- [ ] All tests pass
- [ ] No new linting errors
- [ ] Commit messages are clear

## Coding Standards

### Python Style

We follow PEP 8 with some modifications:

- Line length: 100 characters
- Use Black for formatting
- Use isort for import sorting
- Type hints encouraged

### Example Code Style

```python
"""
Module docstring explaining purpose.
"""

from typing import List, Optional

from emberscan.core.config import Config
from emberscan.core.logger import get_logger

logger = get_logger(__name__)


class MyScanner:
    """
    Class docstring with description.
    
    Attributes:
        config: Scanner configuration
    """
    
    def __init__(self, config: Config) -> None:
        """Initialize scanner with configuration."""
        self.config = config
    
    def scan(self, target: str) -> List[dict]:
        """
        Perform scan on target.
        
        Args:
            target: Path or URL to scan
            
        Returns:
            List of findings
            
        Raises:
            ScannerError: If scan fails
        """
        logger.info(f"Scanning {target}")
        # Implementation
        return []
```

### Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Formatting
- `refactor`: Code restructuring
- `test`: Tests
- `chore`: Maintenance

Examples:
```
feat(scanner): add CSRF detection to web scanner

fix(extract): handle encrypted SquashFS images

docs(readme): update installation instructions
```

## Testing

### Test Structure

```python
"""Tests for firmware extractor."""

import pytest
from pathlib import Path

from emberscan.extractors import FirmwareExtractor


class TestFirmwareExtractor:
    """Test cases for FirmwareExtractor."""
    
    @pytest.fixture
    def extractor(self, config):
        """Create extractor instance."""
        return FirmwareExtractor(config)
    
    def test_analyze_firmware(self, extractor, sample_firmware):
        """Test firmware analysis."""
        result = extractor.analyze(sample_firmware)
        
        assert result['architecture'] is not None
        assert result['file_size'] > 0
    
    def test_extract_squashfs(self, extractor, squashfs_firmware, tmp_path):
        """Test SquashFS extraction."""
        rootfs = extractor.extract(squashfs_firmware, str(tmp_path))
        
        assert rootfs.exists()
        assert (rootfs / 'bin').exists()
```

### Test Categories

- **Unit tests**: `tests/unit/` - Test individual functions
- **Integration tests**: `tests/integration/` - Test component interactions
- **End-to-end tests**: `tests/e2e/` - Test full workflows

## Documentation

### Docstrings

Use Google-style docstrings:

```python
def function(arg1: str, arg2: int = 10) -> bool:
    """
    Short description.
    
    Longer description if needed.
    
    Args:
        arg1: Description of arg1
        arg2: Description of arg2 (default: 10)
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When arg1 is empty
        
    Example:
        >>> function("test", 20)
        True
    """
```

### Adding Documentation

1. Update docstrings in code
2. Add to `docs/` if needed
3. Update README if user-facing

## Adding New Features

### Adding a New Scanner

1. Create scanner file: `emberscan/scanners/my_scanner.py`

2. Implement scanner class:
   ```python
   from .base import BaseScanner, ScannerRegistry
   
   @ScannerRegistry.register('my_scanner')
   class MyScanner(BaseScanner):
       @property
       def name(self) -> str:
           return "my_scanner"
       
       def scan(self, target, firmware, **kwargs):
           # Implementation
           pass
   ```

3. Add to `__init__.py`

4. Add tests in `tests/test_my_scanner.py`

5. Update documentation

### Adding Device Support

1. Add vendor patterns to `firmware_extractor.py`
2. Add CVEs to `cve_scanner.py`
3. Test with real firmware samples
4. Document in README

## Questions?

- Open an issue for bugs or features
- Start a discussion for questions
- Tag maintainers for urgent matters

Thank you for contributing! 🙏
