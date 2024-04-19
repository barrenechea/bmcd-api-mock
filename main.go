package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/bmc", handleBMCRequest)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
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

func handleBMCRequest(w http.ResponseWriter, r *http.Request) {
	var data interface{}

	if r.URL.Query().Get("opt") == "set" {
		data = handleSetRequest(w, r)
	} else {
		data = handleGetRequest(w, r)
	}

	respondWithJSON(w, data)
}

func handleSetRequest(w http.ResponseWriter, r *http.Request) interface{} {
	switch r.URL.Query().Get("type") {
	case "power":
		handleSetPowerRequest(r)
	case "node_info":
		handleSetNodeInfoRequest(w, r)
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
				Result: map[string]interface{}{
					"mode":  "Device",
					"node":  "Node 1",
					"route": "AlternativePort",
				},
			},
		},
	}
}
