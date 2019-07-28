# WebSite First Protection

WebSite First Protection is a golang application for scanning website files for detect malwares.

## This Project/code is based on:
- [PHP Malware Finder](https://github.com/nbs-system/php-malware-finder)
- [Web Malware Scanner](https://github.com/redteamcaliber/WebMalwareScanner)

## Functionalities
  - Scan files on VirusTotal website (check **NOTICE** topic for information about it)
  - Whitelist files
  - Signatures check
  - log output format
  - Scan plain text files (.php, .js)

## Notice
When use VirusTotal.com scan option you need pay attention to the rules of The Virus Total API.
- The VirtusTotal public API is limited to 4 requests per minute.
- The VirtusTotal public API **must not** be used in commercial products or services.

## Usage
Create a API KEY on virtustotal.com and put in WebSiteFirstProtection.go (line 80)

```bash
WebSiteFirstProtection scan -path=/var/www/html -log
WebSiteFirstProtection monitor -path=/var/www/html -vt -log
```
Options:
- scan: Scan files once
- monitor: monitoring files
- vt: use virustotal.com to check files
- log: use to output log format

## Date options for log format

In WebSiteFirstProtection.go change **const layout** line 78 to adjust date format output.

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
