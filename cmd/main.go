package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/nutthanonn/reskill/pkg/utils"
)

var red = color.New(color.FgRed).SprintFunc()
var green = color.New(color.FgGreen).SprintFunc()

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func checkMisconfigCSP(csp string) {
	insecureDirectives := []string{
		"unsafe-inline",
		"unsafe-eval",
		"unsafe-dynamic",
	}

	for _, directive := range insecureDirectives {
		if strings.Contains(csp, directive) {
			formattedString := fmt.Sprintf("- %s: %s", green("Content-Security-Policy"), red(csp))
			fmt.Println(formattedString)
		}
	}

	fmt.Printf("- %s: %s\n", green("Content-Security-Policy"), csp)
}

func ensureScheme(domain string) string {
	u, err := url.Parse(domain)
	if err != nil || u.Scheme == "" {
		return "https://" + domain
	}
	return domain
}

func checkHeaders(resp *http.Response) {
	checkList := []string{
		"X-Frame-Options",
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Content-Security-Policy",
		"Cache-Control",
		"Pragma",
		"Expires",
		"Server",
	}

	lowercaseHeaders := make(map[string][]string)
	for key, value := range resp.Header {
		lowercaseHeaders[strings.ToLower(key)] = value
	}

	fmt.Printf("- %s: %s\n", "Status Code", resp.Status)

	for _, header := range checkList {
		if _, ok := lowercaseHeaders[strings.ToLower(header)]; !ok {
			fmt.Printf("- Missing %s\n", red(header))
		} else {
			if strings.ToLower(header) == "content-security-policy" {
				checkMisconfigCSP(strings.Join(lowercaseHeaders[strings.ToLower(header)], ""))
			} else {
				fmt.Printf("- %s: %s\n", green(header), strings.Join(lowercaseHeaders[strings.ToLower(header)], " "))
			}
		}
	}
}

func main() {
	utils.Banner()
	utils.Information("This tool will check the security headers of the provided URLs")

	var domains []string
	var customHeaders stringSlice

	flag.Var(&customHeaders, "H", "Add a custom header to the request (e.g., -H \"User-Agent: MyAgent\"). Can be used multiple times.")
	flag.Parse()

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		domains = append(domains, sc.Text())
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
		return
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, domain := range domains {
		domainWithScheme := ensureScheme(domain)

		req, err := http.NewRequest("GET", domainWithScheme, nil)
		if err != nil {
			utils.Error(fmt.Sprintf("Failed to create request for %s: %s", domainWithScheme, err.Error()))
			continue
		}

		for _, header := range customHeaders {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			} else {
				utils.Error(fmt.Sprintf("Invalid header format: %s. Expected Key:Value", header))
				continue
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			utils.Error(fmt.Sprintf("Failed to fetch %s: %s", domainWithScheme, err.Error()))
			continue
		}

		defer resp.Body.Close()
		utils.Success(domainWithScheme)

		checkHeaders(resp)
		fmt.Println("--------------------------------------------------------------")

	}
}
