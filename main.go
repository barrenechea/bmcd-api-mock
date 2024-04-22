package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jaswdr/faker/v2"
	"github.com/rs/cors"
)

const (
	serverPort = ":4460"
	corsMaxAge = 300
)

type ResponseObject struct {
	Response []ResponseResult `json:"response"`
}

type ResponseResult struct {
	Result interface{} `json:"result"`
}

type NodeInfo struct {
	PowerState *int32  `json:"power_state,omitempty"`
	Name       *string `json:"name,omitempty"`
	ModuleName *string `json:"module_name,omitempty"`
}

var powerState = map[string]*NodeInfo{
	"Node1": {},
	"Node2": {},
	"Node3": {},
	"Node4": {},
}

var usbState = map[string]string{
	"mode":  "Host",
	"node":  "Node 1",
	"route": "AlternativePort",
}

var networkState = map[string]string{
	"mac": "",
	"ip":  "",
}

func main() {
	// Generate initial state for MAC Address and IP Address
	faker := faker.New()
	networkState["mac"] = strings.ToLower(faker.Internet().MacAddress())
	networkState["ip"] = faker.Internet().LocalIpv4()

	// Start the server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/bmc", handleBMCRequest)
	mux.HandleFunc("/api/bmc/backup", handleBMCBackupRequest)
	mux.HandleFunc("/api/bmc/upload/", handleUploadRequest)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link", "Content-Disposition"},
		AllowCredentials: true,
		MaxAge:           corsMaxAge,
	})

	log.Printf("Server is running on port %s", serverPort)
	go updateBootTime()
	log.Fatal(http.ListenAndServe(serverPort, c.Handler(mux)))
}

func updateBootTime() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		for _, node := range powerState {
			if node != nil && node.PowerState != nil {
				bootTime := *node.PowerState + 1
				node.PowerState = &bootTime
			}
		}
	}
}

func respondWithJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding response: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func handleBMCBackupRequest(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/bmc/backup" {
		handleBackupRequest(w)
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

func handleBMCRequest(w http.ResponseWriter, r *http.Request) {
	var data interface{}

	if r.URL.Query().Get("opt") == "set" {
		data = handleSetRequest(w, r)
	} else {
		data = handleGetRequest(w, r)
	}

	if data != nil {
		respondWithJSON(w, data)
	}
}

func handleBackupRequest(w http.ResponseWriter) {
	currentTime := time.Now().Format("02-01-2006")
	filename := fmt.Sprintf("tp2-backup-%s.tar.gz", currentTime)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))

	// Create a dummy txt file
	dummyContent := []byte("This is a dummy backup file.")

	// Create a new gzip writer
	gzipWriter := gzip.NewWriter(w)
	defer gzipWriter.Close()

	// Create a new tar writer
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Create a new file header
	header := &tar.Header{
		Name: "dummy.txt",
		Mode: 0600,
		Size: int64(len(dummyContent)),
	}

	// Write the header to the tar archive
	if err := tarWriter.WriteHeader(header); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write the dummy file content to the tar archive
	if _, err := tarWriter.Write(dummyContent); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func handleSetRequest(w http.ResponseWriter, r *http.Request) interface{} {
	switch r.URL.Query().Get("type") {
	case "power":
		handleSetPowerRequest(r)
	case "node_info":
		handleSetNodeInfoRequest(w, r)
	case "reset":
		handleSetResetNodeRequest(w, r)
	case "usb":
		handleSetUSBModeRequest(w, r)
	case "network":
		handleResetNetworkState()
	case "firmware":
		handleSetFirmwareRequest(w, r)
		return nil
	case "flash":
		handleSetNodeFlashRequest(w, r)
		return nil
	}

	return setResponse()
}

func handleGetRequest(w http.ResponseWriter, r *http.Request) interface{} {
	switch r.URL.Query().Get("type") {
	case "info":
		return getInfoResponse()
	case "power":
		return getPowerResponse()
	case "about":
		return getAboutResponse()
	case "node_info":
		return getNodeInfoResponse()
	case "usb":
		return getUSBInfoResponse()
	case "firmware":
		handleGetFirmwareState(w)
		return nil
	case "flash":
		handleGetFlashState(w)
		return nil
	default:
		w.Write([]byte("hello world"))
		return nil
	}
}

func handleResetNetworkState() {
	faker := faker.New()
	networkState["mac"] = strings.ToLower(faker.Internet().MacAddress())
	networkState["ip"] = faker.Internet().LocalIpv4()
}

type FlashState struct {
	sync.Mutex
	TransferState map[int64]TransferInfo
}

type TransferInfo struct {
	ID               int64  `json:"id"`
	ProcessName      string `json:"process_name"`
	Size             int64  `json:"size"`
	Cancelled        bool   `json:"cancelled"`
	BytesWritten     int64  `json:"bytes_written"`
	calculatedSha256 string
	expectedSha256   string
}

var flashState = FlashState{
	TransferState: make(map[int64]TransferInfo),
}

func handleUploadRequest(w http.ResponseWriter, r *http.Request) {
	// Extract the handle from the URL
	handleStr := filepath.Base(r.URL.Path)
	log.Printf("Received upload request for handle: %s", handleStr)
	handle, err := strconv.ParseInt(handleStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid handle", http.StatusBadRequest)
		return
	}

	// Check if the transfer info exists
	flashState.Lock()
	transferInfo, exists := flashState.TransferState[handle]
	flashState.Unlock()
	if !exists {
		http.Error(w, "Invalid handle", http.StatusBadRequest)
		return
	}

	// Parse the multipart form
	err = r.ParseMultipartForm(200 * 1024 * 1024) // max 200 MB
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the file from the form
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sha256Checksum := hex.EncodeToString(hash.Sum(nil))

	// Update the transfer info
	flashState.Lock()
	transferInfo.Size = header.Size
	transferInfo.BytesWritten = 0
	transferInfo.calculatedSha256 = sha256Checksum
	flashState.TransferState[handle] = transferInfo
	flashState.Unlock()

	// Return a success response
	w.WriteHeader(http.StatusOK)
}

func handleSetNodeFlashRequest(w http.ResponseWriter, r *http.Request) {
	node := r.URL.Query().Get("node")
	filename := r.URL.Query().Get("file")
	length := r.URL.Query().Get("length")
	sha256 := r.URL.Query().Get("sha256") // optional
	nodeInt, errNodeInt := strconv.ParseInt(node, 10, 64)
	lengthInt, errLengthInt := strconv.ParseInt(length, 10, 64)

	if node == "" || filename == "" || length == "" || errNodeInt != nil || errLengthInt != nil {
		respondWithJSON(w, map[string]string{
			"error": "missing parameters",
		})
		return
	}

	// Generate a unique handle for the transfer
	handle := time.Now().UnixNano()

	// Clean up previous handles for the same node
	nodeKey := fmt.Sprintf("Node %s", strconv.FormatInt(nodeInt+1, 10))
	for handle, info := range flashState.TransferState {
		if info.ProcessName == nodeKey+" os install service" {
			delete(flashState.TransferState, handle)
		}
	}

	// Create a new transfer info entry
	flashState.Lock()
	flashState.TransferState[handle] = TransferInfo{
		ID:             handle,
		ProcessName:    fmt.Sprintf("Node %s os install service", strconv.FormatInt(nodeInt+1, 10)),
		Size:           lengthInt,
		Cancelled:      false,
		BytesWritten:   0,
		expectedSha256: sha256,
	}
	flashState.Unlock()

	// Return the handle as the response
	respondWithJSON(w, map[string]int64{
		"handle": handle,
	})
}

func handleSetFirmwareRequest(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	length := r.URL.Query().Get("length")
	sha256 := r.URL.Query().Get("sha256") // optional
	lengthInt, err := strconv.ParseInt(length, 10, 64)

	if filename == "" || length == "" || err != nil {
		respondWithJSON(w, map[string]string{
			"error": "missing parameters",
		})
		return
	}

	// Generate a unique handle for the transfer
	handle := time.Now().UnixNano()

	// Clean up previous handles for firmware upgrade
	for handle, info := range flashState.TransferState {
		if info.ProcessName == "firmware upgrade service" {
			delete(flashState.TransferState, handle)
		}
	}

	// Create a new transfer info entry
	flashState.Lock()
	flashState.TransferState[handle] = TransferInfo{
		ID:             handle,
		ProcessName:    "firmware upgrade service",
		Size:           lengthInt,
		Cancelled:      false,
		BytesWritten:   0,
		expectedSha256: sha256,
	}
	flashState.Unlock()

	// Return the handle as the response
	respondWithJSON(w, map[string]int64{
		"handle": handle,
	})
}

func handleSetPowerRequest(r *http.Request) {
	for idx := 1; idx <= 4; idx++ {
		nodeKey := fmt.Sprintf("node%d", idx)
		nodeValue := r.URL.Query().Get(nodeKey)
		if nodeValue != "" {
			internalNodeKey := fmt.Sprintf("Node%d", idx)

			if nodeValue == "0" {
				powerState[internalNodeKey].PowerState = nil
			} else {
				value := int32(1)
				powerState[internalNodeKey].PowerState = &value
			}
		}
	}
}

func handleSetResetNodeRequest(w http.ResponseWriter, r *http.Request) {
	nodeStr := r.URL.Query().Get("node")
	if nodeStr == "" {
		// Return an error response if the "node" parameter is missing
		http.Error(w, "Missing 'node' parameter", http.StatusBadRequest)
		return
	}

	nodeNum, err := strconv.Atoi(nodeStr)
	if err != nil {
		// Return an error response if the "node" parameter is not a valid integer
		http.Error(w, "Parameter 'node' is not a number", http.StatusBadRequest)
		return
	}

	if nodeNum < 0 || nodeNum > 3 {
		// Return an error response if the "node" parameter is out of range
		http.Error(w, "Parameter 'node' is out of range 0..3 of node IDs", http.StatusBadRequest)
		return
	}

	internalNodeKey := fmt.Sprintf("Node%d", nodeNum+1)
	if node, exists := powerState[internalNodeKey]; exists {
		value := int32(1)
		node.PowerState = &value
	}
}

func handleSetNodeInfoRequest(w http.ResponseWriter, r *http.Request) {
	var receivedData map[string]NodeInfo
	if err := json.NewDecoder(r.Body).Decode(&receivedData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for nodeKey, info := range receivedData {
		if node, exists := powerState[nodeKey]; exists {
			node.Name = info.Name
			node.ModuleName = info.ModuleName
		}
	}
}

func handleSetUSBModeRequest(w http.ResponseWriter, r *http.Request) {
	modeStr := r.URL.Query().Get("mode")
	nodeStr := r.URL.Query().Get("node")

	if modeStr == "" || nodeStr == "" {
		http.Error(w, "Missing 'mode' or 'node' parameter", http.StatusBadRequest)
		return
	}

	mode, err := strconv.Atoi(modeStr)
	if err != nil {
		http.Error(w, "Parameter 'mode' is not a number", http.StatusBadRequest)
		return
	}

	node, err := strconv.Atoi(nodeStr)
	if err != nil {
		http.Error(w, "Parameter 'node' is not a number", http.StatusBadRequest)
		return
	}

	// Perform the necessary logic to set the USB mode based on the mode and node values
	// Update the USB configuration based on the mode and node
	// You can use the logic from the provided Rust code as a reference
	// Update the USB mode and node information based on the incoming request
	if mode == 0 {
		usbState["mode"] = "Host"
	} else if mode == 1 {
		usbState["mode"] = "Device"
	} else if mode == 2 {
		usbState["mode"] = "Flash"
	}
	usbState["node"] = fmt.Sprintf("Node %d", node+1)
}

func setResponse() ResponseObject {
	return ResponseObject{
		Response: []ResponseResult{
			{
				Result: "ok",
			},
		},
	}
}

func handleGetFlashState(w http.ResponseWriter) {
	flashState.Lock()
	defer flashState.Unlock()

	var response interface{}

	if len(flashState.TransferState) > 0 {
		// If there is an active transfer, send the transfer info
		var transferInfo TransferInfo
		var completedHandle int64

		for handle, info := range flashState.TransferState {
			if !info.Cancelled {
				if info.expectedSha256 != "" && info.expectedSha256 != info.calculatedSha256 {
					response = map[string]string{
						"Error": fmt.Sprintf("sha256 checksum failed. Expected: %s, got: %s", info.expectedSha256, info.calculatedSha256),
					}
					respondWithJSON(w, response)
					return
				}
				// Autoincrement BytesWritten by adding Size
				info.BytesWritten += info.Size
				flashState.TransferState[handle] = info

				if info.BytesWritten >= info.Size*10 {
					// If BytesWritten reaches 10 times the Size, mark the handle as completed
					completedHandle = handle
					transferInfo = info
					break
				} else {
					transferInfo = info
					break
				}
			}
		}

		if completedHandle != 0 {
			log.Printf("Completed transfer with handle: %d", completedHandle)
			// If there is a completed transfer, send the "Done" response
			response = map[string]interface{}{
				"Done": []interface{}{
					map[string]int64{
						"secs":  10,
						"nanos": 100000000,
					},
					transferInfo.Size,
				},
			}
			delete(flashState.TransferState, completedHandle)
		} else {
			// If there is an active transfer, send the "Transferring" response
			response = map[string]interface{}{
				"Transferring": transferInfo,
			}
		}
	} else {
		// If there are no active transfers, send the "Done" response
		response = map[string]interface{}{
			"Done": []interface{}{
				map[string]int64{
					"secs":  0,
					"nanos": 0,
				},
				0,
			},
		}
	}

	respondWithJSON(w, response)
}

func handleGetFirmwareState(w http.ResponseWriter) {
	flashState.Lock()
	defer flashState.Unlock()

	var response interface{}

	if len(flashState.TransferState) > 0 {
		// If there is an active transfer, send the transfer info
		var transferInfo TransferInfo
		var completedHandle int64

		for handle, info := range flashState.TransferState {
			if !info.Cancelled {
				if info.expectedSha256 != "" && info.expectedSha256 != info.calculatedSha256 {
					response = map[string]string{
						"Error": fmt.Sprintf("sha256 checksum failed. Expected: %s, got: %s", info.expectedSha256, info.calculatedSha256),
					}
					respondWithJSON(w, response)
					return
				}
				// Autoincrement BytesWritten by adding Size
				info.BytesWritten += info.Size
				flashState.TransferState[handle] = info

				if info.BytesWritten >= info.Size*10 {
					// If BytesWritten reaches 10 times the Size, mark the handle as completed
					completedHandle = handle
					transferInfo = info
					break
				} else {
					transferInfo = info
					break
				}
			}
		}

		if completedHandle != 0 {
			log.Printf("Completed firmware upgrade with handle: %d", completedHandle)
			// If there is a completed transfer, send the "Done" response
			response = map[string]interface{}{
				"Done": []interface{}{
					map[string]int64{
						"secs":  28,
						"nanos": 10101682,
					},
					transferInfo.Size,
				},
			}
			delete(flashState.TransferState, completedHandle)
		} else {
			// If there is an active transfer, send the "Transferring" response
			response = map[string]interface{}{
				"Transferring": transferInfo,
			}
		}
	} else {
		// If there are no active transfers, send the "Done" response
		response = map[string]interface{}{
			"Done": []interface{}{
				map[string]int64{
					"secs":  0,
					"nanos": 0,
				},
				0,
			},
		}
	}

	respondWithJSON(w, response)
}

func getInfoResponse() ResponseObject {
	return ResponseObject{
		Response: []ResponseResult{
			{
				Result: map[string]interface{}{
					"ip": []map[string]string{
						{
							"device": "eth0",
							"ip":     networkState["ip"],
							"mac":    networkState["mac"],
						},
					},
					"storage": []map[string]interface{}{
						{
							"name":        "BMC",
							"bytes_free":  int32(24948736),
							"total_bytes": int32(25128960),
						},
					},
				},
			},
		},
	}
}

func getPowerResponse() ResponseObject {
	return ResponseObject{
		Response: []ResponseResult{
			{
				Result: map[string]string{
					"node1": "0",
					"node2": "0",
					"node3": "0",
					"node4": "0",
				},
			},
		},
	}
}

func getAboutResponse() ResponseObject {
	return ResponseObject{
		Response: []ResponseResult{
			{
				Result: map[string]interface{}{
					"api":           "1.1",
					"build_version": "2024.02",
					"buildroot":     "Buildroot 2024.02",
					"buildtime":     "2024-04-08 13:45:19-00:00",
					"hostname":      "turingpi\n", // why does it come with a newline from the server?
					"version":       "2.0.5",
				},
			},
		},
	}
}

func getNodeInfoResponse() ResponseObject {
	return ResponseObject{
		Response: []ResponseResult{
			{
				Result: []map[string]interface{}{
					{
						"name":          powerState["Node1"].Name,
						"module_name":   powerState["Node1"].ModuleName,
						"power_on_time": powerState["Node1"].PowerState,
						"uart_baud":     nil,
					},
					{
						"name":          powerState["Node2"].Name,
						"module_name":   powerState["Node2"].ModuleName,
						"power_on_time": powerState["Node2"].PowerState,
						"uart_baud":     nil,
					},
					{
						"name":          powerState["Node3"].Name,
						"module_name":   powerState["Node3"].ModuleName,
						"power_on_time": powerState["Node3"].PowerState,
						"uart_baud":     nil,
					},
					{
						"name":          powerState["Node4"].Name,
						"module_name":   powerState["Node4"].ModuleName,
						"power_on_time": powerState["Node4"].PowerState,
						"uart_baud":     nil,
					},
				},
			},
		},
	}
}

func getUSBInfoResponse() ResponseObject {
	return ResponseObject{
		Response: []ResponseResult{
			{
				Result: usbState,
			},
		},
	}
}
