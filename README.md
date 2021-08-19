
This is a PE file parser that retrieves strings, which are printed to a separate file, hashes, section data, imports/libraries, enotropy and other PE file information. It will then query VirusTotal and print a clear report from any returned data. The new VirusTotal V3 API costs money if you want to get AV detection information, but is still free, although more concise, with the V2 API, hence using both APIs for as much free info as you can get. See the apeParser.txt file for sample output. I did not include a sample of the strings file as it is long and tedious, and you probably already know what will look like. You can run apeParser.py with the "-h" flag for the short help menu. This is by no means an exhaustive list of all PE info, but it is all relevant to malware analysis\reverse engineering. This is an exercise in working with the pefile python library, and gaining some experience with third party APIs. This is a great beginner tool to get you started and thinking about what else you might do with a parsing tool. Enjoy. All thoughts and ideas are welcome.
