import vt
import re
import asyncio

inputFilename = "input.txt"
apiKey = "e135f7110c3ed4eb0a5686e02378ccb1ca916210fa57bc51e1dd10c8ac81481c"
ipRegex = "^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$"
urlRegex = re.compile(
    r'^(?:http|ftp)s?://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
    r'localhost|'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)  # Extracted from Django URL validator


async def ipScan(client, queries):
    tasks = []
    for query in queries:
        # Adding the async ops into the task queue
        tasks.append(client.get_object_async(f"/ip_addresses/{query}"))
    # Execute the tasks in the task queue cocurrently
    ipResponses = await asyncio.gather(*tasks)
    for resp in ipResponses:
        ipScanned = resp.id
        vtAnalysis = resp.last_analysis_stats
        print("-"*100)
        print(f"URL Scanned: {ipScanned}")
        print(
            f'Results:\nHarmless: {vtAnalysis["harmless"]} | Malicious: {vtAnalysis["malicious"]} | Suspicious: {vtAnalysis["suspicious"]} | Timeout: {vtAnalysis["timeout"]} | Undetected: {vtAnalysis["undetected"]}')
        print("-"*100)


async def urlScan(client, queries):
    tasks = []
    for query in queries:
        url_id = vt.url_id(query)
        # Adding the async ops into the task queue
        tasks.append(client.get_object_async(f"/urls/{url_id}"))
    # Execute the tasks in the task queue cocurrently
    urlResponses = await asyncio.gather(*tasks)
    for resp in urlResponses:
        urlScanned = resp.url
        vtAnalysis = resp.last_analysis_stats
        print("-"*100)
        print(f"URL Scanned: {urlScanned}")
        print(
            f'Results:\nHarmless: {vtAnalysis["harmless"]} | Malicious: {vtAnalysis["malicious"]} | Suspicious: {vtAnalysis["suspicious"]} | Timeout: {vtAnalysis["timeout"]} | Undetected: {vtAnalysis["undetected"]}')
        print("-"*100)


async def fileScan(client, queries):
    tasks = []
    for query in queries:
        # Adding the async ops into the task queue
        tasks.append(client.get_object_async(f"/files/{query}"))
    # Execute the tasks in the task queue cocurrently
    fileResponses = await asyncio.gather(*tasks)
    for resp in fileResponses:
        print("-"*100)
        if resp.md5 in queries:
            print(f"MD5 Hash Scanned: {resp.md5}")
        elif resp.sha1 in queries:
            print(f"SHA1 Hash Scanned: {resp.sha1}")
        else:
            print(f"SHA256 Hash Scanned: {resp.sha256}")
        vtAnalysis = resp.last_analysis_stats
        print(
            f'Results:\nHarmless: {vtAnalysis["harmless"]} | Malicious: {vtAnalysis["malicious"]} | Suspicious: {vtAnalysis["suspicious"]} | Timeout: {vtAnalysis["timeout"]} | Undetected: {vtAnalysis["undetected"]}')
        print("-"*100)


async def main():
    # Reading input file containing the queries to be made
    try:
        with open(inputFilename, 'r', encoding="utf-8") as file:
            queries = file.read().split()
    except:
        print("Error occurred with reading the file")
    # 3 separate tasks queue: IP, URL, Files (SHA256, SHA1 etc)
    ipQueries = []
    urlQueries = []
    fileQueries = [
        "f511ab5caf5aaa548fb901a01105f843c88c33e83231ac8350dc31797bfe7f66"]

    for query in queries:
        if re.search(ipRegex, query):
            # Identify if input is an IPv4 address
            ipQueries.append(query)
        elif re.search(urlRegex, query):
            urlQueries.append(query)
        else:
            fileQueries.append(query)
    print(
        f"IPv4 Query Queue: {ipQueries}\nURL Query Queue: {urlQueries}\nFile Query Queue: {fileQueries}")
    client = vt.Client(apiKey)
    await asyncio.gather(ipScan(client, ipQueries), urlScan(client, urlQueries),
                         fileScan(client, fileQueries))
    await client.close_async()

if __name__ == "__main__":
    asyncio.run(main())
