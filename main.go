package main

import (
    "bufio"
    "fmt"
    "os"
    "net/http"
    "github.com/fatih/color"
    "strings"
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
            formattedString := fmt.Sprintf("Content-Security-Policy: %s", red(csp))
            fmt.Println(formattedString)
        }
    }
}

func main() {
    var domains []string
    red := color.New(color.FgRed).SprintFunc()
    green := color.New(color.FgGreen).SprintFunc()

    sc := bufio.NewScanner(os.Stdin)
    for sc.Scan() {
        domains = append(domains, sc.Text())
    }

    if err := sc.Err(); err != nil {
        fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
    }

    for _, domain := range domains {
        color.Cyan(domain)

        resp, err := http.Get(domain)
        if err != nil {
            fmt.Printf("Error fetching the URL: %v\n", err)
            continue
        }
        defer resp.Body.Close()

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

        for _, header := range check_list {
            if _, ok := lowercaseHeaders[strings.ToLower(header)]; !ok {
                formattedString := fmt.Sprintf("Missing %s", red(header))
                fmt.Println(formattedString)

            } else {
                if header == "Content-Security-Policy" {
                    checkMisconfigCSP(strings.Join(lowercaseHeaders[strings.ToLower(header)], ""))
                } else {
                    formattedString := fmt.Sprintf("%s: %s", green(header), strings.Join(lowercaseHeaders[strings.ToLower(header)], " "))
                    fmt.Println(formattedString)
                }
            }
        }
        fmt.Println("----------------------------------------")

    }
}