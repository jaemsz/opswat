# OPSWAT interview question

### Task
Create an application that will scan a specified file

### Approach
1. Compute file SHA2 of specified file
2. Check metadefender cloud if it has a record of SHA2
    * METHOD: GET
    * URL: https://api.metadefender.com/v4/hash/:hash
4. If yes, then go to 7
5. If the SHA2 is not present, then upload file to metadefender cloud
    * METHOD: POST
    * URL: https://api.metadefender.com/v4/file
6. Poll metadefender every 10 seconds for 60 seconds (default)
    * METHOD: GET
    * URL: https://api.metadefender.com/v4/file/:data_id
7. Display scan result
    * filename
    * overall status
    * scan result for each AV engine
      * threat_found
      * scan_result_i
      * def_time
