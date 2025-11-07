# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## 2025-11-07 - 0.8.7

### First release

- Initial release of DomainTools Iris Investigate integration module
- Domain reputation analysis action to assess domain risk scores
- Pivot search action supporting multiple indicator types:
  - Domain pivoting for infrastructure connections
  - IP address pivoting for reverse lookups
  - Email address pivoting for registrant searches
  - Nameserver hostname pivoting for DNS infrastructure analysis
- Reverse domain lookup action for hosting history
- Reverse IP action to find domains on the same IP
- Reverse email action to find domains registered with the same email
- Complete domain lookup action for comprehensive investigation data
- Comprehensive JSON schemas for all action response structures with detailed field descriptions
- Input validation for domains, IPs, and email addresses
- HMAC-based API authentication with secure credential handling
- Retry logic for transient failures with exponential backoff
- Rate limiting protection to prevent API abuse
- Comprehensive test suite with 39 test cases and 79.95% code coverage
- 100% code coverage on all action handler files
- Mypy type checking configuration for code quality assurance
- Black code formatter configuration for consistent code style
