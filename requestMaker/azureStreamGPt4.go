package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/ai/azopenai"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/uuid"
	"golang.org/x/net/http2"
)

var (
	apiClient struct {
		client      *azopenai.Client
		endpoint    string
		accessToken string
		mu          sync.RWMutex
	}
)

func main() {
	// set  this to azure deployment name of your model
	deploymentName := flag.String("model", "gpt-4o-test", "Model name for Azure OpenAI")

	// Parse the flags
	flag.Parse()

	// DO NOT CHANGE THE LOCAL ENDPOINT below AS THAT HITS THE SERVER MADE IN PREVIOUS STEP
	endpoint := flag.String("endpoint", "https://localhost:8443", "Azure OpenAI endpoint")
	client, err := GetAPIClient(*endpoint, "")
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	ctx := context.Background()

	req := azopenai.ChatCompletionsOptions{
		DeploymentName: deploymentName,
		MaxTokens:      intToInt32Ptr(4000),
		Messages:       getChatMessages([]Message{{Speaker: HUMAN_MESSAGE_SPEAKER, Text: "hello?"}}),
	}

	resp, err := client.GetChatCompletionsStream(ctx, req, nil)
	if err != nil {
		log.Fatalf("ChatCompletion error: %v", err)
	}
	defer resp.ChatCompletionsStream.Close()

	var content string

	for {
		entry, err := resp.ChatCompletionsStream.Read()
		// stream is done
		if errors.Is(err, io.EOF) {
			// Handle token usage calculation if needed
			// tokenManager := tokenusage.NewManager()
			// err = tokenManager.TokenizeAndCalculateUsage(req.Messages, content, "azure-model-name", "chat_completions", tokenusage.AzureOpenAI)
			// if err != nil {
			// 	log.Printf("Failed to count tokens with the token manager: %v", err)
			// }
			break
		}
		// some other error has occurred
		if err != nil {
			log.Fatalf("Stream read error: %v", err)
		}
		if hasValidFirstChatChoice(entry.Choices) {
			// hasValidFirstChatChoice checks that Delta.Content isn't null
			// it is marked as REQUIRED in docs despite being a pointer
			newContent := *entry.Choices[0].Delta.Content
			content += newContent

			finish := ""
			// FinishReason is marked as REQUIRED but it's nil until the end
			if entry.Choices[0].FinishReason != nil {
				finish = string(*entry.Choices[0].FinishReason)
			}
			ev := CompletionResponse{
				Completion: newContent,
				StopReason: finish,
			}
			err := sendEvent(ev)
			if err != nil {
				log.Fatalf("Failed to send event: %v", err)
			}
		}
	}

}

// Custom policy to add multiple headers and log the request
type addHeadersPolicy struct {
	headers map[string]string
}

func (p *addHeadersPolicy) Do(req *policy.Request) (*http.Response, error) {
	for key, value := range p.headers {
		req.Raw().Header.Set(key, value)
	}

	return req.Next()
}

func sendEvent(ev CompletionResponse) error {
	// For now, just log the event
	fmt.Println("  ", ev.Completion)
	return nil
}

func hasValidFirstChatChoice(choices []azopenai.ChatChoice) bool {
	return choices != nil && len(choices) > 0 && choices[0].Delta.Content != nil
}

type CompletionResponse struct {
	Completion string    `json:"completion"`
	StopReason string    `json:"stopReason"`
	Logprobs   *Logprobs `json:"logprobs,omitempty"`
}
type Logprobs struct {
	Tokens        []string             `json:"tokens"`
	TokenLogprobs []float32            `json:"token_logprobs"`
	TopLogprobs   []map[string]float32 `json:"top_logprobs"`
	TextOffset    []int32              `json:"text_offset"`
}

const HUMAN_MESSAGE_SPEAKER = "human"
const ASSISTANT_MESSAGE_SPEAKER = "assistant"

type Message struct {
	Speaker string `json:"speaker"`
	Text    string `json:"text"`
}

func getChatMessages(messages []Message) []azopenai.ChatRequestMessageClassification {
	azureMessages := make([]azopenai.ChatRequestMessageClassification, len(messages))
	for i, m := range messages {
		message := m.Text
		switch m.Speaker {
		case HUMAN_MESSAGE_SPEAKER:
			azureMessages[i] = &azopenai.ChatRequestUserMessage{Content: azopenai.NewChatRequestUserMessageContent(message)}
		case ASSISTANT_MESSAGE_SPEAKER:
			azureMessages[i] = &azopenai.ChatRequestAssistantMessage{Content: &message}
		}

	}
	return azureMessages
}

func intToInt32Ptr(i int) *int32 {
	v := int32(i)
	return &v
}

type apiVersionRoundTripper struct {
	rt         http.RoundTripper
	apiVersion string
}

func (rt *apiVersionRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	newReq := req.Clone(req.Context())
	values := newReq.URL.Query()
	values.Set("api-version", rt.apiVersion)
	newReq.URL.RawQuery = values.Encode()
	return rt.rt.RoundTrip(newReq)
}

func apiVersionClient(apiVersion string) *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	azureClientDefaultTransport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:    tls.VersionTLS12,
			Renegotiation: tls.RenegotiateFreelyAsClient,
		},
	}

	if http2Transport, err := http2.ConfigureTransports(azureClientDefaultTransport); err == nil {
		http2Transport.ReadIdleTimeout = 10 * time.Second
		http2Transport.PingTimeout = 5 * time.Second
	}

	return &http.Client{
		Transport: &apiVersionRoundTripper{
			rt:         azureClientDefaultTransport,
			apiVersion: apiVersion,
		},
	}
}

func generateHeaders(bearerToken string) map[string]string {
	return map[string]string{
		"correlationId":      uuid.New().String(),
		"dataClassification": "sensitive",
		"dataSource":         "internet",
		"Authorization":      "Bearer " + bearerToken,
	}
}

func GetAPIClient(endpoint, accessToken string) (*azopenai.Client, error) {
	clientOpts := &azopenai.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: apiVersionClient("2023-05-15"),
			PerRetryPolicies: []policy.Policy{
				&addHeadersPolicy{
					headers: generateHeaders(accessToken),
				},
			},
		},
	}
	var err error
	credential := azcore.NewKeyCredential(accessToken)
	apiClient.client, err = azopenai.NewClientWithKeyCredential(endpoint, credential, clientOpts)
	return apiClient.client, err
}
