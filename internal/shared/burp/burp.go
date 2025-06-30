package burp

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"

	"errors"

	"github.com/charmbracelet/log"
	"github.com/go-gota/gota/dataframe"
)

type BurpXML struct {
	XMLName     xml.Name `xml:"issues"`
	BurpVersion string   `xml:"burpVersion,attr"`
	ExportTime  string   `xml:"exportTime,attr"`
	Issues      []Issue  `xml:"issue"`
}

type Issue struct {
	SerialNumber                 string            `xml:"serialNumber"`
	Type                         string            `xml:"type"`
	Name                         string            `xml:"name"`
	Host                         Host              `xml:"host"`
	Path                         string            `xml:"path"`
	Location                     string            `xml:"location"`
	Severity                     string            `xml:"severity"`
	Confidence                   string            `xml:"confidence"`
	IssueBackground              *string           `xml:"issueBackground,omitempty"`
	RemediationBackground        *string           `xml:"remediationBackground,omitempty"`
	References                   *string           `xml:"references,omitempty"`
	VulnerabilityClassifications *string           `xml:"vulnerabilityClassifications,omitempty"`
	IssueDetail                  string            `xml:"issueDetail"`
	IssueDetailItems             *IssueDetailItems `xml:"issueDetailItems,omitempty"`
	RemediationDetail            *string           `xml:"remediationDetail,omitempty"`
	RequestResponses             []RequestResponse `xml:"requestresponse"`
}

type Host struct {
	IP   string `xml:"ip,attr"`
	Name string `xml:",chardata"`
}

type IssueDetailItems struct {
	Items []string `xml:"issueDetailItem"`
}

type RequestResponse struct {
	Request            *Request  `xml:"request,omitempty"`
	Response           *Response `xml:"response,omitempty"`
	ResponseRedirected *string   `xml:"responseRedirected,omitempty"`
}

type Request struct {
	Method string `xml:"method,attr"`
	Base64 string `xml:"base64,attr"`
	Value  string `xml:",chardata"`
}

type Response struct {
	Base64 string `xml:"base64,attr"`
	Value  string `xml:",chardata"`
}

func ParseFile(filename string) (*BurpXML, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Debug("burp.ParseFile", "filename", filename, "Error", err)
		return nil, err
	}
	var report BurpXML
	err = xml.Unmarshal(data, &report)
	if err != nil {
		log.Debug("burp.ParseFile", "filename", filename, "Error", err)
		return nil, err
	}
	return &report, nil
}

func ToDataFrame(burp BurpXML) (*dataframe.DataFrame, error) {

	hosts := []string{}
	vulntitle := []string{}
	location := []string{}
	vulndetails := []string{}

	for _, vuln := range burp.Issues {
		hosts = append(hosts, vuln.Host.IP)
		vulntitle = append(vulntitle, vuln.Name)
		url := fmt.Sprintf("%s%s", vuln.Host.Name, vuln.Path)
		location = append(location, url)
		vulndetails = append(vulndetails, vuln.IssueDetail)
		log.Debug("burp.ToDataFrame", "Host", vuln.Host.IP, "Vuln", vuln.Name, "Location", url)
	}

	rows := []map[string]any{}
	for i := range hosts {
		rows = append(rows, map[string]any{
			"Host":    hosts[i],
			"Title":   vulntitle[i],
			"URL":     location[i],
			"Details": vulndetails[i],
		})
	}

	df := dataframe.LoadMaps(rows)
	df = df.Select([]string{"Host", "Title", "URL", "details"})
	return &df, nil
}

func ParseJSVulns(burp BurpXML) (*dataframe.DataFrame, error) {
	anchor := regexp.MustCompile(`<a href="https?://nvd\.nist\.gov/vuln/detail/(CVE-\d{4}-\d{4,7})">CVE-\d{4}-\d{4,7}</a>:\s*(.*?)<br>`)

	hosts := []string{}
	location := []string{}
	vulntitle := []string{}
	cve := []string{}
	vulndetails := []string{}
	reference := []string{}

	for _, vuln := range burp.Issues {
		if vuln.Type != "5243008" {
			log.Debug("burp.ParseJSVulns ID mismatch", "id", vuln.Type)
			continue
		}
		matches := anchor.FindAllStringSubmatch(vuln.IssueDetail, -1)
		if len(matches) > 0 {
			for _, i := range matches {
				url := fmt.Sprintf("%s%s", vuln.Host.Name, vuln.Path)
				location = append(location, url)
				hosts = append(hosts, vuln.Host.IP)
				vulntitle = append(vulntitle, vuln.Name)
				cve = append(cve, i[1])
				vulndetails = append(vulndetails, i[2])
				reference = append(reference, fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", i[1]))
				log.Debug("burp.ParseJSVulns Match", "url", location, "title", vulntitle, "cve", cve)
			}
		}
	}

	rows := []map[string]any{}
	if len(location) > 0 {
		for i := range location {
			rows = append(rows, map[string]any{
				"Host":      hosts[i],
				"URL":       location[i],
				"Title":     vulntitle[i],
				"CVE":       cve[i],
				"Reference": reference[i],
				"Details":   vulndetails[i],
			})
		}
	} else {
		return nil, errors.New("no valid entries found")
	}

	df := dataframe.LoadMaps(rows)
	df = df.Select([]string{"Host", "Title", "URL", "Details", "CVE", "Reference"})

	return &df, nil
}
