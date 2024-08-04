# Reskill

Reskill is an automated tool designed to hunt for missing HTTP security headers and insecure Content Security Policy (CSP) configurations from a given wordlist.

## Features

- Automates the detection of missing HTTP security headers.
- Identifies insecure CSP configurations.
- Utilizes a customizable wordlist for targeted scanning.

## Installation

To install Reskill, clone the repository and build the project using Go:

```bash
git clone https://github.com/nutthanonn/reskill.git
cd reskill
go build
```

## Usage

```bash
cat urls.txt | reskill
cat urls.txt | reskill --dedupe
```
