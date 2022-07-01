# VTScanner

Designed a simple VirusTotal scanner leveraging the VirusTotal V3 API
All IPv4 addresses, File hashes (SHA256, SHA1, MD5) & URLs are to be placed in the same directory as main[.]py file
The scanner will open the file & proceed to scan the information provided in the Input[.]txt file.

To improve the speed of the program, the code has been designed to run asychronously via the usage of AsyncIO + AIOHttp packages.

Feel free to copy the code for your own usage or let me know what can be improved. Cheers!
