import vt
import re
import asyncio

inputFilename = "input.txt"
apiKey = "USE YOUR OWN API KEY FROM VIRUST TOTAL"
ipRegex = "^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$"
urlRegex = re.compile(
    r'^(?:http|ftp)s?://'
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
    r'localhost|'
    r'(?::\d+)?'
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)  # Extracted from Django URL validator


async def urlScan(client, queries):
    tasks = []
    for query in queries:
        url_id = vt.url_id(query)
        # Adding the async ops into the task queue
        tasks.append(client.get_object_async(f"/urls/{url_id}"))
    # Execute the tasks in the task queue cocurrently
    urlResponses = await asyncio.gather(*tasks)
    for resp in urlResponses:
        print(resp.last_analysis_stats)


async def fileScan(client, queries):
    tasks = []
    for query in queries:
        # Adding the async ops into the task queue
        tasks.append(client.get_object_async(f"/files/{query}"))
    # Execute the tasks in the task queue cocurrently
    fileResponses = await asyncio.gather(*tasks)
    for resp in fileResponses:
        print(resp.last_analysis_stats)


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
    await asyncio.gather(urlScan(client, urlQueries),
                         fileScan(client, fileQueries))
    await client.close_async()

if __name__ == "__main__":
    asyncio.run(main())
