import hashlib
import json
import multiprocessing
import os
import pprint
import requests
import sys
import time
from requests_toolbelt.multipart.encoder import MultipartEncoder

"""
NOTES:
    File types tested:
    1.  PE files
    2.  Office documents
    3.  Archive files (zip, 7z)
    4.  Polyglot (zip,pdf)
"""


# Register for a free account at portal.opswat.com.
# Copy and paste your API key here
APIKEY = "<API KEY>"


def metadefender_cloud_hash_scan(file_sha256):
    """
    Lookup scan results using file SHA256
    Input:  file SHA256
    Return: metadefender JSON response containing
            scan results, else None
    """
    headers = {
        "apikey" : APIKEY,
    }

    # Make a request to metadefender cloud to scan file SHA256
    response = requests.get("https://api.metadefender.com/v4/hash/" + file_sha256, headers=headers)
    return json.loads(response.text)


def metadefender_cloud_file_scan(file_path):
    """
    Upload file to metadefender cloud
    Input:  file path
    Return: metadefender JSON response containing
            data_id
    """
    file_size = os.path.getsize(file_path)
    file_name = os.path.split(file_path)[1]

    # if file size is greater than 10 MB, send file in chunks
    if file_size > 10485760:
        # https://docs.python-requests.org/en/latest/user/quickstart/#post-a-multipart-encoded-file
        # https://toolbelt.readthedocs.io/en/latest/uploading-data.html#streaming-multipart-data-encoder
        m = MultipartEncoder(
            fields = {
                "files": (file_name, open(file_path, "rb"), "application/octet-stream")
            })

        headers = {
            "apikey" : APIKEY,
            "filename" : file_name,
            "rule" : "unarchive",
            "content-type" : m.content_type,
        }

        response = requests.post("https://api.metadefender.com/v4/file", headers=headers, data=m)
        return json.loads(response.text)

    else:
        headers = {
            "apikey" : APIKEY,
            "filename" : file_name,
            "rule" : "unarchive",
            "content-type" : "application/octet-stream"
        }

        # Read file contents
        data = ""
        with open(file_path, "rb") as f:
            data = f.read()
        
        # Make a request to metadefender cloud to scan the file
        response = requests.post("https://api.metadefender.com/v4/file", headers=headers, data=data)
        return json.loads(response.text)


def metadefender_cloud_file_scan_poll(data_id, timeout=60):
    """
    Poll metadefender cloud for scan results
    Input:  data_id of uploaded file
            timeout value in seconds (default is 60)
    Return: metadefender JSON response containing
            scan results, else None
    """
    headers = {
        "apikey" : APIKEY,
    }

    cnt = 0
    while cnt < timeout / 10:
        # Make a request to metadefender cloud for scan progress
        response = requests.get("https://api.metadefender.com/v4/file/" + data_id, headers=headers)
        if response.status_code == 200:
            response_json = json.loads(response.text)
            if response_json["scan_results"]["progress_percentage"] == 100:
                # scan is done, so return the scan results
                return response_json
            # sleep for 10 seconds before making the next request
            time.sleep(10)
            cnt += 1
        else:
            break
    
    return None


def display_scan_result(scan_result):
    """
    Display the metadefender scan results
    Input: scan results
    Output: output engine scan results to stdout
    """
    filename = scan_result["file_info"]["display_name"]
    overall_status = scan_result["scan_results"]["scan_all_result_a"]

    print(f"filename: {filename}")
    print(f"overall_status: {overall_status}")

    for scan_engine in scan_result["scan_results"]["scan_details"]:
        print(f"engine: {scan_engine}")

        threat_found = scan_result["scan_results"]["scan_details"][scan_engine]["threat_found"]
        print(f"threat_found: {threat_found}")

        scan_result_i = scan_result["scan_results"]["scan_details"][scan_engine]["scan_result_i"]
        print(f"scan_result_i: {scan_result_i}")

        def_time = scan_result["scan_results"]["scan_details"][scan_engine]["def_time"]
        print(f"def_time: {def_time}")


def get_file_sha256(file_path):
    """
    Compute file SHA256 of file
    Input: file path
    Return: SHA256 string
    """
    if not os.path.exists(file_path):
        return None

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def main(file_path):
    # Get file SHA256
    file_sha256 = get_file_sha256(file_path)
    if not file_sha256:
        print(f"ERROR: {file_path} does not exist")
        return

    print(f"INFO: SHA256 of {file_path} is {file_sha256}")

    try:
        # Scan the file SHA256
        scan_result = metadefender_cloud_hash_scan(file_sha256)

        if "error" in scan_result and scan_result["error"]["code"] == 404003:
            print(f"INFO: Metadefender does not have a record of {file_sha256}")
            print(f"INFO: Uploading {file_sha256} to Metadefender cloud")
            
            # File SHA256 does not exist on metadefender cloud, so
            # upload the file
            scan_result = metadefender_cloud_file_scan(file_path)

            if "error" in scan_result:
                print(f"ERROR: {';'.join(scan_result['error']['messages'])}")
                return

            if "status" in scan_result and scan_result["status"] == "inqueue":
                print(f"INFO: {file_sha256} added to the scan queue")
                print(f"INFO: data_id = {scan_result['data_id']}")
                print("INFO: Polling metadefender cloud for scan results")

                # The file has been added to the queue, so
                # now let's just poll metadefender for scan result
                scan_result = metadefender_cloud_file_scan_poll(scan_result["data_id"])
                if not scan_result:
                    print("ERROR: Scan timed out.  Try increasing the timeout value.")
                else:
                    display_scan_result(scan_result)
            
            else:
                # Something unexpected happened
                print("ERROR: Unexpected metadefender cloud scan return value")

        elif "error" in scan_result:
            # Handle all other type of errors here (ie. invalid key)
            print(f"ERROR: {';'.join(scan_result['error']['messages'])}")

        else:
            # File SHA256 found, so display scan result
            display_scan_result(scan_result)
        
    except requests.exceptions.ConnectionError:
        print(f"ERROR: Check your network connection")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("USAGE: python opswat.py [path to file]")
    else:
        main(sys.argv[1])
