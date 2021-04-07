# OPSWAT interview question

### Task
Create an application that will scan a specified file using metadefender cloud API.

### Approach
1. Compute file SHA2 of specified file
2. Check metadefender cloud if it has a record of SHA2
    * METHOD: GET
    * URL: https://api.metadefender.com/v4/hash/:hash
3. If yes, then go to 6
4. If the SHA2 is not present, then upload file to metadefender cloud
    * METHOD: POST
    * URL: https://api.metadefender.com/v4/file
5. Poll metadefender for scan result every 10 seconds for 60 seconds (default)
    * METHOD: GET
    * URL: https://api.metadefender.com/v4/file/:data_id
6. Display scan result
    * filename
    * overall status
    * scan result for each AV engine
      * threat_found
      * scan_result_i
      * def_time

### Usage
1. Install python 3.x
2. pip install requests
3. python opswat.py [path to file]

### Unexpected observations
1. Expected a list of files in the archive in the scan result, but did not see it in my testing.  As a result, I did not implement any code to handle this case.

### Polygot files
1. Polygot zip/pdf test case file was recognized as zip only.
'file_info': {'display_name': 'S(b5)-Zip-PDF.3f780187.pdf.zip',
               'file_size': 515,
               'file_type_category': 'A',
               'file_type_description': 'ZIP Archive',
               'file_type_extension': 'zip',
               'md5': '361EEC79FFB4680BD47FCC6FE43D2AFD',
               'sha1': 'BD1F3879538DBCA6146F15406E3267605BB000D0',
               'sha256': '3F78018715E8DCAEB2C03A594FAC30F052E0CEE5CFE329D517C0C972ED1C469C',
               'upload_timestamp': '2021-04-07T03:02:24.069Z'},

### Test cases
1. PE files
2. Office documents
3. Archive files (zip, 7z)
4. Polyglot (zip,pdf)


### Alternative Approach
Create a web application that will do the above, but also utilize web hooks to recieve scan result instead of polling for it.
