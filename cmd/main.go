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
}

func deduplicateUrls(urls []string) []string {
	uniquePaths := make(map[string]bool)
	var result []string

	for _, rawUrl := range urls {
		parsedUrl, err := url.Parse(rawUrl)
		if err != nil {
			continue
		}

		// Build the base URL without the query parameters
		baseUrl := fmt.Sprintf("%s://%s%s", parsedUrl.Scheme, parsedUrl.Host, parsedUrl.Path)

		// Check if the base URL is already in the map
		if _, exists := uniquePaths[baseUrl]; !exists {
			uniquePaths[baseUrl] = true
			result = append(result, baseUrl)
		}
	}

	return result
}

func removeStatic(urls []string) []string {
	uniquePaths := make(map[string]bool)
	var result []string
	extension := []string{".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".ico"}

	for _, rawUrl := range urls {
		parsedUrl, err := url.Parse(rawUrl)
		if err != nil {
			continue
		}

		baseUrl := parsedUrl.Scheme + "://" + parsedUrl.Host + parsedUrl.Path
		isStatic := false
		for _, ext := range extension {
			if strings.HasSuffix(baseUrl, ext) {
				isStatic = true
				break
			}
		}

		if isStatic {
			continue
		}

		if parsedUrl.RawQuery != "" {
			baseUrl += "?" + parsedUrl.RawQuery
		}

		if _, exists := uniquePaths[baseUrl]; !exists {
			uniquePaths[baseUrl] = true
			result = append(result, baseUrl)
		}
	}

	return result
}

func main() {
	utils.Banner()
	utils.Information("This tool will check the security headers of the provided URLs")

	var domains []string
	var urlDedupe bool
	flag.BoolVar(&urlDedupe, "dedupe", false, "Deduplicate URLs")
	flag.Parse()

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		domains = append(domains, sc.Text())
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
	}

	if urlDedupe {
		domains = deduplicateUrls(domains)
	}

	domains = removeStatic(domains)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, domain := range domains {
		resp, err := client.Get(domain)
		if err != nil {
			utils.Error(err.Error())
			continue
		}

		defer resp.Body.Close()
		utils.Success(domain)

		check_list := []string{
			"X-Frame-Options",
			"Strict-Transport-Security",
			"X-Content-Type-Options",
			"X-XSS-Protection",
			"Content-Security-Policy",
		}

		lowercaseHeaders := make(map[string][]string)
		for key, value := range resp.Header {
			lowercaseHeaders[strings.ToLower(key)] = value
		}

		formattedString := fmt.Sprintf("- %s: %s", "Status Code", resp.Status)
		fmt.Println(formattedString)

		for _, header := range check_list {
			if _, ok := lowercaseHeaders[strings.ToLower(header)]; !ok {
				formattedString := fmt.Sprintf("- Missing %s", red(header))
				fmt.Println(formattedString)

			} else {
				if header == "Content-Security-Policy" {
					checkMisconfigCSP(strings.Join(lowercaseHeaders[strings.ToLower(header)], ""))
				} else {
					formattedString := fmt.Sprintf("- %s: %s", green(header), strings.Join(lowercaseHeaders[strings.ToLower(header)], " "))
					fmt.Println(formattedString)
				}
			}
		}
		fmt.Println("--------------------------------------------------------------")

	}
}
