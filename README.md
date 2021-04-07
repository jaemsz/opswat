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
2. Expected the file upload API to return right away if an invalid key was specified, but it took longer than expected.  Maybe this is by design?

### Alternative Approach
Create a web application that will do the above, but also utilize web hooks to recieve scan result instead of polling for it.
