package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Define our scan object
type ScanObject struct {
	apikey      string
	filePath    string
	fileSha256  string
	dataId      string
	scanDetails map[string]interface{}
}

func (scanObj *ScanObject) computeFileSha256() error {
	// Check if the file exists
	if _, err := os.Stat(scanObj.filePath); err != nil {
		return errors.New("file does not exist")
	}

	// Open the file
	file, err := os.Open(scanObj.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a SHA256 object
	hash := sha256.New()
	// Calculate the SHA256 for the file
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}

	// Save the file SHA256 as a string in our scan object
	// We will use it to scan the SHA256 using metadefender hash scan API
	scanObj.fileSha256 = hex.EncodeToString(hash.Sum(nil))
	return nil
}

func (scanObj *ScanObject) scanSha256() error {
	// Create a request to do a metadefender hash scan on our SHA256
	req, err := http.NewRequest("GET", "https://api.metadefender.com/v4/hash/"+scanObj.fileSha256, nil)
	if err != nil {
		return err
	}

	// Add the apikey to the header
	req.Header.Add("apikey", scanObj.apikey)

	// Creae a client and make the request
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	// Read the response from the server
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	// Parse the response as a JSON data
	var mdRes map[string]interface{}
	err = json.Unmarshal([]byte(body), &mdRes)
	if err != nil {
		return err
	}

	// Check if "error" field is in the JSON data
	if _, found := mdRes["error"]; found {
		return errors.New("file is not in metadefender database")
	}

	// Save the scan_details in our scan object, so we
	// can use it to display to stdout
	scanRes := mdRes["scan_results"].(map[string]interface{})
	scanObj.scanDetails = scanRes["scan_details"].(map[string]interface{})
	return nil
}

func (scanObj *ScanObject) uploadScanFile() error {
	// Stole some code from the following URL
	// https://matt.aimonetti.net/posts/2013-07-golang-multipart-file-upload-example/

	// Open the file
	file, err := os.Open(scanObj.filePath)
	if err != nil {
		return err
	}

	defer file.Close()

	// Allocate a buffer for multipart/form-data
	body := &bytes.Buffer{}
	// Create a writer to our buffer
	writer := multipart.NewWriter(body)
	// Tell the writer to create the multipart/form-data field
	part, err := writer.CreateFormFile("file", filepath.Base(scanObj.filePath))
	if err != nil {
		return err
	}

	// Populate the multipart/form-data field
	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	// Create a post request to call the metadefender upload API
	// Set the body of the request with the multipart/form-data
	req, err := http.NewRequest("POST", "https://api.metadefender.com/v4/file", body)
	if err != nil {
		return err
	}

	// Add the necessary headers
	req.Header.Add("apikey", scanObj.apikey)
	req.Header.Set("content-type", writer.FormDataContentType())

	// Create a HTTP client and make the request
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	// Get the response from the server
	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	// Parse the response body as JSON data
	var mdRes map[string]interface{}
	err = json.Unmarshal([]byte(resBody), &mdRes)
	if err != nil {
		return err
	}

	// Check if "error" is a field in the JSON data
	if _, found := mdRes["error"]; found {
		// "error" is found, so let's return the error
		return errors.New("file is not in metadefender database")
	}

	// Save the data_id to our scan object, so we can use it
	// for polling the scan results
	scanObj.dataId = mdRes["data_id"].(string)
	return nil
}

func (scanObj *ScanObject) pollScanResult() error {
	// Create a GET request to poll scan results using the data_id we got from
	// the server on the upload API call
	req, err := http.NewRequest("GET", "https://api.metadefender.com/v4/file/"+scanObj.dataId, nil)
	if err != nil {
		return err
	}

	// Add our apikey to the header
	req.Header.Add("apikey", scanObj.apikey)

	// Create a HTTP client and make the request
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	// Counter for the infinite loop below
	// If count == 6, return an error
	count := 0

	for {
		// Read the response body
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}

		// Parse the response body as JSON data
		var mdRes map[string]interface{}
		err = json.Unmarshal([]byte(body), &mdRes)
		if err != nil {
			return err
		}

		// Get the scan_results field from the JSON object
		scanRes := mdRes["scan_results"].(map[string]interface{})
		// Get the progress_percentage field from the scan_results field
		progPercent := scanRes["progress_percentage"].(float64)

		// Check if the progress_percentage field value is 100
		if progPercent == 100 {
			// Save the scan_details field in our scan object
			scanObj.scanDetails = scanRes["scan_details"].(map[string]interface{})
			break
		}

		// Sleep for 10 seconds before trying again
		time.Sleep(10 * time.Second)

		if count == 6 {
			return errors.New("failed to get scan result within a 60 seconds")
		}

		// Make the request
		res, err = client.Do(req)
		if err != nil {
			return err
		}
	}

	return nil
}

func (scanObj *ScanObject) displayScanResult() {
	// Enumerate the scan_details field and display
	// all the scan results from the various
	// scan engines that metadefender uses
	for key, val := range scanObj.scanDetails {
		fmt.Println("Scan Engine: " + key)

		scanEngDetails := val.(map[string]interface{})

		fmt.Printf("%s: %s\n", "threat_found", scanEngDetails["threat_found"].(string))
		fmt.Printf("%s: %.f\n", "scan_time", scanEngDetails["scan_time"].(float64))
		fmt.Printf("%s: %.f\n", "scan_result_i", scanEngDetails["scan_result_i"].(float64))
		fmt.Printf("%s: %s\n", "def_time", scanEngDetails["def_time"].(string))
	}
}

func main() {
	// Parse the command line
	apiKey := flag.String("k", "", "API key")
	filePath := flag.String("f", "", "File")
	flag.Parse()

	// Initialize our file object
	scanObj := ScanObject{filePath: *filePath, apikey: *apiKey}

	fmt.Println("INFO: file = " + *filePath)

	if err := scanObj.computeFileSha256(); err != nil {
		// Failed to compute SHA256
		log.Fatal(err)
	} else {
		fmt.Println("INFO: SHA256 = " + scanObj.fileSha256)

		if err := scanObj.scanSha256(); err != nil {
			// File does not exist in Metadefender database,
			// so let's upload the file
			if err := scanObj.uploadScanFile(); err != nil {
				// File upload failed
				log.Fatal(err)
			} else {
				// File upload succeeded, so let's poll
				// Metadefender cloud for scan result
				if err := scanObj.pollScanResult(); err != nil {
					// Polling for scan result failed
					log.Fatal(err)
				} else {
					// Display the scan result
					scanObj.displayScanResult()
				}
			}
		} else {
			// File SHA256 scan succeeded, so let's display
			// the scan result
			scanObj.displayScanResult()
		}
	}
}
