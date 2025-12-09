# SecureAgent

![Tests](https://github.com/armstrongsam25/SecureAgent/actions/workflows/test.yml/badge.svg)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12%20|%203.13-blue)

This repository contains the Dynamic Authorization Framework (DAF) for AI Agents. It is designed to provide "Identity as Code" for agentic workflows, abstracting away the complexities of OIDC and Keycloak.

## 📦 Agentic Security Package

The core of this project is the `agentic-security` Python package. It provides a high-level API for agents to automatically register themselves and exchange tokens securely.

**[👉 Go to Agentic Security Package](./agentic-security/README.md)**

### Key Features
- **Zero-Touch Registration**: Agents auto-register with the Identity Provider on first boot.
- **Auto-Validation**: Easy-to-use FastAPI dependencies for token verification.
- **Token Exchange**: Simple API to exchange user tokens for downstream service access (RFC 8693).

---

## 🧪 Proof of Concept (Legacy)

The `poc/` directory contains the original scripts and experiments used to validate the architecture. It serves as a reference implementation and test bed.

**[👉 Go to POC Documentation](./poc/README.md)**

## Project Structure

- `agentic-security/`: The reusable, pip-installable package.
- `poc/`: Experimental scripts and raw implementation files.
