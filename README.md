# BackdoorMan (Under active development)

### Description
A Python open source toolkit that helps you find malicious, hidden and suspicious PHP scripts and shells in a chosen destination, it automates the process of detecting the above.

### Purpose
The main purpose of `BackdoorMan` is to help web-masters and developers to discover malicious scripts in their site files, because it is quite common for hackers to place a back-door on a site they have hacked. A back-door can give the hacker continued access to the site even if the site owners change account passwords. Back-door scripts will vary from 100s of lines of code to 1 or 2 lines of code and can be merged in hundreds of files which makes it very hard to discover it, especially if the back-door is inactive. There is common ways and tools that can be used including `grep`, but `BackdoorMan` automates all the above as described earlier and make it even more easier (at least I hope so).

### Features
- Shells detect by filename using shells signature database.
- Recognition of web back-doors.
- Detect the use of suspicious PHP functions and activities.
- Use of external services beside its functionalities.
- Use of nimbusec shellray API (free online webshell detect for PHP files https://shellray.com).
  - Very high recognition performance for webshells.
  - Check suspicious PHP files online.
  - Easy, fast and reliable.
  - Classification for webshells with behavior classification.
  - Free service of nimbusec.
- Use of VirusTotal Public API (free online service that analyzes files and facilitates the quick detection of viruses, worms, trojans and all kinds of malware), it can be useful in our situation.
- Use of UnPHP (The online PHP decoder: UnPHP is a free service for analyzing obfuscated and malicious PHP code) www.unphp.net. Very useful in our situation.
	- Eval + gzinflate + Base64.
	- Recursive De-Obfuscating.
	- Custom Function and Regex Support.

### Requirements
- requests module

### Version
`v2.2.1`

### Author
Yassine Addi

### Disclaimer

### License
`BackdoorMan` is released under the [MIT License](http://www.opensource.org/licenses/mit-license.php).

### Usage
```
Usage: BackdoorMan [options] destination1 [destination2 ...]

A toolkit that helps you find malicious, hidden and suspicious PHP scripts and
shells in a chosen destination.

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -f, --force           force scan non PHP files
  --no-color            do not use colors in the output
  --no-file-info        do not show file information
  --no-external-services
                        do not use external services during scan
```

### Changelog
```
v1.0.0    1st release <https://github.com/yassineaddi/PHP-backdoor-detector>.
v2.0.0    - rename software to `BackdoorMan`.
          - improve external services (APIs).
          - separate databases from main script.
          - lot of improvements (compare with 1st release).
v2.1.0    - separate script to classes to optimize the software.
v2.2.0    - add `Servicer` class.
          - rename classes.
          - add `--no-color` option.
          - add `--no-external-services` option.
          - add `--no-file-info` option.
          - improve `Reporter` class.
          - improve software interface.
          - small improvements.
          - remove single-line and multi-line comments before scanning.
          - add `--force` option.
          - add UnPHP API.
          - improve `activities.txt` database.
v2.2.1    - modify comments.
```

### TODO
```
- Handle special cases of suspicious activities.
- Add comments.
- Improve reg-ex(s).
```
