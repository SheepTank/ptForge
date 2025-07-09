package nessus

import (
	"encoding/xml"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/go-gota/gota/dataframe"
)

const NessusRiskInfo int = 0
const NessusRiskLow int = 1
const NessusRiskMedium int = 2
const NessusRiskHigh int = 3
const NessusRiskCritical int = 4

const NessusSSLPluginList string = "31705 57582 157288 104743 42873 104743 157288 51192 20007 65821 31705 78479 15901 35291 45411"
const NessusInfoPluginList string = "10107 149334 149334"
const NessusSSHDetectionPlugin string = "10267"

var NessusSeverities = map[int]string{
	0: "INFO",
	1: "LOW",
	2: "MEDIUM",
	3: "HIGH",
	4: "CRITICAL",
}

// region Structs
type NessusReport struct {
	XMLName xml.Name      `xml:"NessusClientData_v2"`
	Report  NessusDetails `xml:"Report"`
}

type NessusDetails struct {
	Hosts []ReportHost `xml:"ReportHost"`
}

type ReportHost struct {
	Name    string   `xml:"name,attr"`
	Plugins []Plugin `xml:"ReportItem"`
}

type Plugin struct { // ReportItem
	Port         int    `xml:"port,attr"`
	PluginID     int    `xml:"pluginID,attr"`
	PluginName   string `xml:"pluginName,attr"`
	Severity     int    `xml:"severity,attr"`
	PluginOutput string `xml:"plugin_output"`
	Host         string // Used during processing
}

// endregion

// region Functions

func ProcessFilter(flag string) []int {
	i := []int{}
	f := strings.Split(flag, " ")
	for _, v := range f {
		if x, err := strconv.Atoi(v); err == nil {
			i = append(i, x)
		} else {
			return []int{}
		}
	}
	return i
}

func FilterNessusPlugins(report *NessusReport, include, exclude string) []Plugin {
	var plugins []Plugin
	filter := map[string][]int{
		"include": {},
		"exclude": {},
	}
	if len(include) > 0 {
		filter["include"] = ProcessFilter(include)
	}
	if len(exclude) > 0 {
		filter["exclude"] = ProcessFilter(exclude)
	}

	log.Debug("nessus.FilterNessusPlugins", "include-ids", filter["include"])
	log.Debug("nessus.FilterNessusPlugins", "exclude-ids", filter["exclude"])

	for _, host := range report.Report.Hosts {
		for _, plugin := range host.Plugins {
			plugin.Host = host.Name
			if len(filter["include"]) > 0 && len(filter["exclude"]) == 0 {
				if slices.Contains(filter["include"], plugin.PluginID) {
					plugins = append(plugins, plugin)
				}
			}
			if len(filter["exclude"]) > 0 && len(filter["include"]) == 0 {
				if !slices.Contains(filter["exclude"], plugin.PluginID) {
					plugins = append(plugins, plugin)
				}
			}
			if len(filter["include"]) == 0 && len(filter["exclude"]) == 0 {
				plugins = append(plugins, plugin)
			}
		}
	}
	return plugins
}

func PluginsToDataFrame(plugins []Plugin, includePluginOutput bool) (*dataframe.DataFrame, error) {

	hosts := []string{}
	ports := []string{}
	pluginIDs := []string{}
	pluginNames := []string{}
	severities := []string{}
	pluginOutputs := []string{}

	for _, plugin := range plugins {
		log.Debug("Nessus Plugin Details", "Host", plugin.Host, "Port", plugin.Port, "Title", plugin.PluginName)
		hosts = append(hosts, plugin.Host)
		pluginIDs = append(pluginIDs, strconv.Itoa(plugin.PluginID))
		ports = append(ports, strconv.Itoa(plugin.Port))
		pluginNames = append(pluginNames, plugin.PluginName)
		severities = append(severities, NessusSeverities[plugin.Severity])
		if includePluginOutput {
			pluginOutputs = append(pluginOutputs, plugin.PluginOutput)
		}
	}

	rows := []map[string]any{}
	for i := range hosts {
		if includePluginOutput {
			rows = append(rows, map[string]any{
				"Host":          hosts[i],
				"Port":          ports[i],
				"Plugin ID":     pluginIDs[i],
				"Title":         pluginNames[i],
				"Severity":      severities[i],
				"Plugin Output": pluginOutputs[i],
			})
		} else {
			rows = append(rows, map[string]any{
				"Host":      hosts[i],
				"Port":      ports[i],
				"Plugin ID": pluginIDs[i],
				"Title":     pluginNames[i],
				"Severity":  severities[i],
			})
		}
	}

	df := dataframe.LoadMaps(rows)
	order := []string{"Host", "Port", "Plugin ID", "Title", "Severity"}

	if includePluginOutput {
		order = append(order, "Plugin Output")
	}

	df = df.Select(order)
	return &df, nil
}

func ParseFile(filename string) (*NessusReport, error) {
	var report NessusReport

	fd, err := os.ReadFile(filename)
	if err != nil {
		log.Debug("nessus.ParseFile", "filename", filename, "Error", err)
		return nil, err
	}

	if err := xml.Unmarshal(fd, &report); err != nil {
		log.Debug("nessus.ParseFile", "filename", filename, "Error", err)
		log.Fatal(err)
		return nil, err
	}
	return &report, nil
}

// endregion
