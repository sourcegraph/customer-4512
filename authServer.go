package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	accessToken   string
	tokenMutex    sync.RWMutex
	client        *http.Client
	azureEndpoint *url.URL // Add this line
)

func updateAccessToken() {
	for {
		token, err := getAccessToken()
		if err != nil {
			log.Printf("Error getting access token: %v", err)
		} else {
			tokenMutex.Lock()
			accessToken = token
			tokenMutex.Unlock()
			log.Println("Access token updated")
		}
		time.Sleep(1 * time.Minute)
	}
}

func initializeAzureEndpoint() {
	var err error
	azureEndpoint, err = url.Parse(os.Getenv("AZURE_ENDPOINT"))
	if err != nil {
		log.Fatalf("Invalid AZURE_ENDPOINT: %v", err)
	}
}

func initializeClient() {
	client = &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        400,
			MaxIdleConnsPerHost: 400,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
		},
		Timeout: 30 * time.Second,
	}
}

func getAccessToken() (string, error) {
	oauth_url := os.Getenv("OAUTH_URL")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")

	authKey := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", clientID, clientSecret)))

	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequest("POST", oauth_url, io.NopCloser(strings.NewReader(data.Encode())))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Add("Authorization", "Basic "+authKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to retrieve token: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("error decoding response: %v", err)
	}

	token, ok := result["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access token not found in response")
	}

	return token, nil
}

func handleProxy(w http.ResponseWriter, req *http.Request) {
	target := azureEndpoint.ResolveReference(req.URL)
	// Create a proxy request
	proxyReq, err := http.NewRequest(req.Method, target.String(), req.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Copy headers from the original request
	for header, values := range req.Header {
		for _, value := range values {
			proxyReq.Header.Add(header, value)
			fmt.Println("header:", header, " value: ", value)
		}
	}

	tokenMutex.RLock()
	bearerToken := accessToken
	tokenMutex.RUnlock()

	proxyReq.Header.Set("Api-Key", bearerToken)

	resp, err := client.Do(proxyReq)
	fmt.Println("client request made")
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Write the headers and status code from the response to the client
	for header, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(header, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Stream the response body to the client
	reader := bufio.NewReader(resp.Body)
	buf := make([]byte, 32*1024)
	for {
		n, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		if n == 0 {
			break
		}
		if _, writeErr := w.Write(buf[:n]); writeErr != nil {
			log.Printf("Error writing response: %v", writeErr)
			break
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
}

func main() {
	initializeClient()
	initializeAzureEndpoint()
	go updateAccessToken()
	http.HandleFunc("/", handleProxy)
	log.Println("HTTPS Proxy server is running on port 8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))
}
