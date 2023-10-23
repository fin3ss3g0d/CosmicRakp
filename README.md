# CosmicRakp

![Thanos Image](./thanos.jpg)

## Table of Contents

- [Introduction](#introduction)
- [CVE-2013-4786](#cve-2013-4786)
- [Installation](#installation)
- [Usage](#usage)
- [Credits](#credits)
- [License](#license)

## Introduction

CosmicRakp is a powerful tool written in Go that allows red teamers and penetration testers to dump IPMI hashes. This project aims to be efficient, fast, and easy to use.

## CVE-2013-4786

This tool exploits the vulnerability detailed in CVE-2013-4786, which allows unauthorized users to retrieve salted password hashes from IPMI devices via the RAKP (Remote Authentication Key Protocol) mechanism. This is achieved by initiating an IPMI 2.0 RAKP authentication process with a cipher suite that enables 'None' authentication, allowing the retrieval of salted password hashes.

## Installation

```bash
./build.sh
```

## Usage

```go
❯ ./cosmicrakp -h
Usage of ./cosmicrakp:
  -debug
    	enable debug mode
  -max-attempts int
    	maximum number of attempts to open a session (default 3)
  -mode string
    	mode of operation: 'range' or 'file' (default "range")
  -output string
    	File to store output results (default "output.txt")
  -range string
    	IP range for 'range' mode
  -retry-delay duration
    	time to wait between retries (in seconds) (default 2s)
  -targets string
    	target file for 'file' mode
  -threads int
    	number of threads for concurrent execution (default 4)
  -usernames string
    	File containing usernames to test (default "users.txt")
```


### Credits

This project is inspired by and pays homage to one of the original (if not the original) proof-of-concept for exploiting CVE-2013-4786. The PoC was developed by Dan Farmer and is a part of the Metasploit Framework. You can find the original code [here](https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/ipmi/ipmi_dumphashes.rb).

### License

This project uses the MIT license.