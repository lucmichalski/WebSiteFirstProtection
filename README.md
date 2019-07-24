# WebSite First Protection

WebSite First Protection is a golang application for scanning website files for detect malwares.

This code is base on the project below:

[Web Malware Scanner](https://github.com/redteamcaliber/WebMalwareScanner)

**All signatures is from WebMalwareScanner.**


## Notice
- There is a option to scan files with virustotal.com
- The VirtusTotal public API is limited to 4 requests per minute.
- The VirtusTotal public API **must not** be used in commercial products or services.
- langagues supported:
  - php
  - js

## Usage

Create a API KEY on virtustotal.com and put in WebSiteFirstProtection.go (line 80)

```bash
website_scan scan -path/var/www/html
website_scan monitor -path=/var/www/html -vt
```
Options:
- scan: Scan files once
- monitor: monitoring files
- vt: use virustotal.com to check files
- log: use to output log format

## Date options for log format

In WebSiteFirstProtection.go change **const layout** line 83 to adjust date format output.

Examples:

```golang
const layout = "2006-01-02T15:04:05"
const layout = "2006-01-02T15:04:05-0700"
const layout = "2 Jan 2006 15:04:05"
const layout = "2 Jan 2006 15:04"
const layout = "Mon, 2 Jan 2006 15:04:05 MST"
```


## Dependences
- [FsNotify](github.com/fsnotify/fsnotify)
- [Terminal Colors for golang](https://godoc.org/github.com/fatih/color)
