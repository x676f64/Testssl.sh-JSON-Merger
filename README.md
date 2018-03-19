# Testssl.sh-JSON-Merger
This quick-n-dirty shell script merges several testssl.sh pretty-JSON files to one single JSON file. Useful if executing an SSL/TLS scan for a large host or IP range and utilizing the testssl2xlsx.py parser for generating a customer spread sheet.

The [testssl.sh](https://github.com/drwetter/testssl.sh) script by drwetter usually only accepts single hosts or IPs to scan.
Nevertheless, using some parallization, one can scan several hosts and store the output in a nice pretty-JSON format.

For each host, you may executed the following to get your json files:\
`./testssl.sh --warnings=batch --openssl-timeout=60 --json-pretty <IP>:<PORT>`

However, if you want to use a parser like [testssl2xlsx.py](https://github.com/AresS31/testssl2xlsx) to generate a nicely formatted spread sheet for your customers etc. you'll notice that it only accepts a single JSON file .. but we've got many of them, since testssl.sh does only scan single-hosts or IPs.

Therefore, we have to merge all *.json files to a single file that works with the parser ;-)

# Usage:
1. Place all your testssl.sh *.json output files into the **/scan/** directory
2. Check the path variable of `testssl2xlsx.py` in the `merge.sh` script
3. Execute with `sh merge.sh`
4. You'll find your spread sheet in the **/scan/** directory.

Note: Your modified testssl.sh *.json output files are stored in the **/backup_scans** folder. -- useless --


