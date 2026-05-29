# Contributing to SubReaper

Thank you for considering contributing to SubReaper!

This document will guide you through the contribution process.

---

## How to Contribute

1. **Fork** the repository on GitHub.

2. **Create a new branch** from `main` for your work:

```bash id="p6n3jv"
git checkout -b feature/my-awesome-feature
```

3. Make your changes and write clear, concise commit messages:

```bash id="7h1v0e"
git commit -m "Add: description of what you did"
```

4. Push your branch to your fork:

```bash id="vxzhp9"
git push origin feature/my-awesome-feature
```

5. Open a Pull Request against the `main` branch of the original repository.

6. Describe your changes and link any related issues.

---

## Development Setup

Clone the repository and install development dependencies:

```bash id="mwt7qd"
git clone https://github.com/rendidwisa/subreaper.git
cd subreaper
pip install -r requirements-dev.txt
```

Run the test suite:

```bash id="0d53gz"
pytest tests/
```

Check code style:

```bash id="m9twl6"
flake8 subreaper/
```

---

## Adding New Service Fingerprints

SubReaper's detection relies on the fingerprint database in `subreaper/data/fingerprints.py`.

To add a new service:

1. Open `subreaper/data/fingerprints.py`.

2. Add a new dictionary to the `TAKEOVER_FINGERPRINTS` list following this structure:

```python id="yhb4v9"
{
    "service": "Service Name",
    "cname_patterns": ["example.com", "example.io"],
    "response_fingerprints": [
        "Exact error text that indicates an unclaimed resource"
    ],
    "http_codes": [404],
    "confidence": "HIGH",  # or MEDIUM/LOW
    "references": "https://docs.example.com"
}
```

3. Run the fingerprint validation tests:

```bash id="s4xq2c"
pytest tests/test_fingerprints.py
```

4. Make sure your new fingerprint does not cause false positives by scanning a test domain.

---

## Reporting Bugs

If you find a bug, please open an issue with:

* A clear title and description
* Steps to reproduce
* Expected vs. actual behavior
* Your environment:

  * OS
  * Python version
  * SubReaper version

---

## Code Guidelines

* Follow PEP 8
* Use type hints where practical
* Write unit tests for new detection logic or utility functions
* Keep the code modular:

  * Place DNS logic in `core/dns_analyzer.py`
  * Place HTTP probing in `core/http_prober.py`

---

Thank you for helping make SubReaper better!
