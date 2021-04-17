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

type File struct {
	filePath    string
	fileSha256  string
	dataId      string
	scanDetails map[string]interface{}
}

func (f *File) computeFileSha256() error {
	if _, err := os.Stat(f.filePath); err != nil {
		return errors.New("File does not exist")
	}

	fileObject, err := os.Open(f.filePath)
	if err != nil {
		return err
	}
	defer fileObject.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, fileObject); err != nil {
		return err
	}

	f.fileSha256 = hex.EncodeToString(hash.Sum(nil))
	return nil
}

func (f *File) scanSha256() error {
	req, err := http.NewRequest("GET", "https://api.metadefender.com/v4/hash/"+f.fileSha256, nil)
	if err != nil {
		return err
	}

	req.Header.Add("apikey", "e964575df55d1c7af6399011da3224d5")

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
		return errors.New("File is not in Metadefender database")
	}

	scanRes := mdRes["scan_results"].(map[string]interface{})
	f.scanDetails = scanRes["scan_details"].(map[string]interface{})
	return nil
}

func (f *File) uploadScanFile() error {
	// Stole some code from the following URL
	// https://matt.aimonetti.net/posts/2013-07-golang-multipart-file-upload-example/
	file, err := os.Open(f.filePath)
	if err != nil {
		return err
	}

	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(f.filePath))
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

	req.Header.Add("apikey", "e964575df55d1c7af6399011da3224d5")
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
		return errors.New("File is not in Metadefender database")
	}

	f.dataId = mdRes["data_id"].(string)
	return nil
}

func (f *File) pollScanResult() error {
	req, err := http.NewRequest("GET", "https://api.metadefender.com/v4/file/"+f.dataId, nil)
	if err != nil {
		return err
	}

	req.Header.Add("apikey", "e964575df55d1c7af6399011da3224d5")

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
			f.scanDetails = scanRes["scan_details"].(map[string]interface{})
			break
		}

		res, err = client.Do(req)
		if err != nil {
			return err
		}
	}

	return nil
}

func (f *File) displayScanResult() {
	for key, val := range f.scanDetails {
		fmt.Println("Scan Engine: " + key)

		scanEngDetails := val.(map[string]interface{})

		for key2, val2 := range scanEngDetails {
			fmt.Println(key2, val2)
		}
	}
}

func main() {
	// Parse the command line
	filePath := flag.String("f", "", "File")
	flag.Parse()

	// Initialize our file object
	file := File{filePath: *filePath}

	if err := file.computeFileSha256(); err != nil {
		// Failed to compute SHA256
		log.Fatal(err)
	} else {
		if err := file.scanSha256(); err != nil {
			// File does not exist in Metadefender database,
			// so let's upload the file
			if err := file.uploadScanFile(); err != nil {
				// File upload failed
				log.Fatal(err)
			} else {
				// File upload succeeded, so let's poll
				// Metadefender cloud for scan result
				if err := file.pollScanResult(); err != nil {
					// Polling for scan result failed
					log.Fatal(err)
				} else {
					// Display the scan result
					file.displayScanResult()
				}
			}
		} else {
			// File SHA256 scan succeeded, so let's display
			// the scan result
			file.displayScanResult()
		}

	}
}
