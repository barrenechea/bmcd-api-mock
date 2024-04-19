package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

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

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/bmc", handleBMCRequest)
	mux.HandleFunc("/api/bmc/backup", handleBMCBackupRequest)

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

	respondWithJSON(w, data)
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
	case "firmware":
		handleSetFirmwareRequest(w, r)
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
	default:
		w.Write([]byte("hello world"))
		return nil
	}
}

func handleSetFirmwareRequest(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(200 * 1024 * 1024) // 200 MB
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	log.Printf("Received firmware file: %s", header.Filename)
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

func getInfoResponse() ResponseObject {
	return ResponseObject{
		Response: []ResponseResult{
			{
				Result: map[string]interface{}{
					"ip": []map[string]string{
						{
							"device": "eth0",
							"ip":     "10.0.0.100",
							"mac":    "12:34:56:78:9a:bc\n", // why does it come with a newline from the server?
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
