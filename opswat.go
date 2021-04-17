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
)

type ScanObject struct {
	apikey      string
	filePath    string
	fileSha256  string
	dataId      string
	scanDetails map[string]interface{}
}

func (scanObj *ScanObject) computeFileSha256() error {
	if _, err := os.Stat(scanObj.filePath); err != nil {
		return errors.New("file does not exist")
	}

	fileObject, err := os.Open(scanObj.filePath)
	if err != nil {
		return err
	}
	defer fileObject.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, fileObject); err != nil {
		return err
	}

	scanObj.fileSha256 = hex.EncodeToString(hash.Sum(nil))
	return nil
}

func (scanObj *ScanObject) scanSha256() error {
	req, err := http.NewRequest("GET", "https://api.metadefender.com/v4/hash/"+scanObj.fileSha256, nil)
	if err != nil {
		return err
	}

	req.Header.Add("apikey", scanObj.apikey)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var mdRes map[string]interface{}
	err = json.Unmarshal([]byte(body), &mdRes)
	if err != nil {
		return err
	}

	if _, found := mdRes["error"]; found {
		return errors.New("file is not in metadefender database")
	}

	scanRes := mdRes["scan_results"].(map[string]interface{})
	scanObj.scanDetails = scanRes["scan_details"].(map[string]interface{})
	return nil
}

func (scanObj *ScanObject) uploadScanFile() error {
	// Stole some code from the following URL
	// https://matt.aimonetti.net/posts/2013-07-golang-multipart-file-upload-example/
	file, err := os.Open(scanObj.filePath)
	if err != nil {
		return err
	}

	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(scanObj.filePath))
	if err != nil {
		return err
	}

	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", "https://api.metadefender.com/v4/file", body)
	if err != nil {
		return err
	}

	req.Header.Add("apikey", scanObj.apikey)
	req.Header.Set("content-type", writer.FormDataContentType())

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var mdRes map[string]interface{}
	err = json.Unmarshal([]byte(resBody), &mdRes)
	if err != nil {
		return err
	}

	if _, found := mdRes["error"]; found {
		return errors.New("file is not in metadefender database")
	}

	scanObj.dataId = mdRes["data_id"].(string)
	return nil
}

func (scanObj *ScanObject) pollScanResult() error {
	req, err := http.NewRequest("GET", "https://api.metadefender.com/v4/file/"+scanObj.dataId, nil)
	if err != nil {
		return err
	}

	req.Header.Add("apikey", scanObj.apikey)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	for {
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}

		var mdRes map[string]interface{}
		err = json.Unmarshal([]byte(body), &mdRes)
		if err != nil {
			return err
		}

		scanRes := mdRes["scan_results"].(map[string]interface{})
		progPercent := scanRes["progress_percentage"].(float64)

		if progPercent == 100 {
			scanObj.scanDetails = scanRes["scan_details"].(map[string]interface{})
			break
		}

		res, err = client.Do(req)
		if err != nil {
			return err
		}
	}

	return nil
}

func (scanObj *ScanObject) displayScanResult() {
	for key, val := range scanObj.scanDetails {
		fmt.Println("Scan Engine: " + key)

		scanEngDetails := val.(map[string]interface{})

		for key2, val2 := range scanEngDetails {
			fmt.Println(key2, val2)
		}
	}
}

func main() {
	// Parse the command line
	apiKey := flag.String("k", "", "API key")
	filePath := flag.String("f", "", "File")
	flag.Parse()

	// Initialize our file object
	scanObj := ScanObject{filePath: *filePath, apikey: *apiKey}

	if err := scanObj.computeFileSha256(); err != nil {
		// Failed to compute SHA256
		log.Fatal(err)
	} else {
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
