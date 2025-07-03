package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"ptForge/internal/shared/burp"
	"ptForge/internal/shared/ctxkeys"
	"ptForge/internal/shared/helper"
	"ptForge/internal/shared/nessus"
	"ptForge/internal/shared/nmap"
	"ptForge/internal/shared/reporting"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/go-gota/gota/dataframe"
)

var version = "0.0.7"

var (
	parseBurp, parseNmap, parseEvidenceDirectory, parseNessusFile     string
	parseNessusIncludeIDs, parseNessusExcludeIDs, outputFileDecorator string

	// Burp
	parseJSVulns bool

	// Gather Functionality
	gatherSSH, gatherSSL bool

	// Nessus
	addPO, reviewSSL, reviewGeneral bool

	parseNmapScripts, formatCSV, formatJSON, formatSTDOUT bool
	outputIPs, outputPorts                                bool
	outputName                                            string

	// ptForge Specific Details
	ctx                         context.Context = context.Background()
	silenceOutput, checkUpdates bool
	checkChangelog              bool
	debugMode                   bool
	devflag                     bool
	ptForgeVersion              bool
	changelog                   []string = []string{
		"Added:",
		"- Integration with Github Tags for version checking.",
	}
)

func init() {
	t := time.Now()
	outname := t.Format(time.DateOnly) + "_" + t.Format(time.TimeOnly) + "_ptForge"
	outname = strings.ReplaceAll(outname, "-", "_")
	outname = strings.ReplaceAll(outname, ":", "-")
	outname = strings.ReplaceAll(outname, " ", "_")
	outputName = outname
}

func main() {
	flag.BoolVar(&reviewSSL, "review-ssl", false, "Extract ssl-related findings from a nessus file. Requires --nessus flag")
	flag.BoolVar(&reviewGeneral, "review-general", false, "Extract some useful informational findings from a nessus file. Requires --nessus flag")
	flag.StringVar(&parseNmap, "nmap", "", "Parse Nmap XML file")
	flag.BoolVar(&parseNmapScripts, "scripts", false, "Parse Nmap XML file to get script results, requires --nmap (Supports ssl-enum-ciphers, ssh2-enum-algos)")
	flag.StringVar(&parseNessusFile, "nessus", "", "Parse Nessus file")
	flag.StringVar(&parseNessusIncludeIDs, "include-ids", "", "Parse specific plugins from a Nessus file")
	flag.StringVar(&parseNessusExcludeIDs, "exclude-ids", "", "Parse specific plugins from a Nessus file")
	flag.StringVar(&outputFileDecorator, "output", "", "Add decorative text to the output file name.")
	flag.BoolVar(&addPO, "addpo", false, "Include detailed output (Nessus plugin output/Burpsuite Requests and Responses)")
	flag.BoolVar(&formatCSV, "csv", false, "Output to CSV Format")
	flag.BoolVar(&formatJSON, "json", false, "Output to JSON Format")
	flag.BoolVar(&formatSTDOUT, "stdout", false, "Output to stdout")
	flag.BoolVar(&outputIPs, "ips", false, "Output IPs")
	flag.BoolVar(&outputPorts, "ports", false, "Output IPs")
	flag.BoolVar(&ptForgeVersion, "version", false, "Show ptForge Version")
	flag.StringVar(&parseBurp, "burp", "", "Extract useful findings from a Burpsuite XML report.")
	flag.BoolVar(&silenceOutput, "s", false, "Silence all ptForge-related output")
	flag.BoolVar(&checkChangelog, "changelog", false, "Show changelog embedded within the file")
	flag.BoolVar(&debugMode, "debug", false, "Set debug mode output")
	flag.BoolVar(&devflag, "dev", false, "Trigger dev functionality")
	flag.StringVar(&parseEvidenceDirectory, "evidence", "", "Parse a directory for evidence")
	flag.BoolVar(&gatherSSH, "gather-ssh", false, "Gather SSH algorithms evidence from Nessus, and create ptForge output")
	flag.BoolVar(&gatherSSL, "gather-ssl", false, "Gather SSL ciphers evidence from Nessus, and create ptForge output")
	flag.BoolVar(&parseJSVulns, "review-js", false, "Extract js-related findings from a burpsuite xml file. Requires --burp flag")
	flag.BoolVar(&checkUpdates, "update", false, "Check for available updates.")
	flag.Parse()

	// Setup Context
	ctx = context.WithValue(ctx, ctxkeys.KeyFormatCSV, formatCSV)
	ctx = context.WithValue(ctx, ctxkeys.KeyFormatJSON, formatJSON)
	ctx = context.WithValue(ctx, ctxkeys.KeyFormatSTDOUT, formatSTDOUT)
	ctx = context.WithValue(ctx, ctxkeys.KeyOutputIPs, outputIPs)
	ctx = context.WithValue(ctx, ctxkeys.KeyOutputPorts, outputPorts)
	ctx = context.WithValue(ctx, ctxkeys.KeyDebugMode, debugMode)
	ctx = context.WithValue(ctx, ctxkeys.KeyVersion, version)

	if silenceOutput {
		log.SetOutput(io.Discard)
	}

	if debugMode {
		log.SetLevel(log.DebugLevel)
		log.SetReportCaller(true)
		log.Debug("Reporting Info", "Flags", []any{"formatCSV", formatCSV, "formatJSON", formatJSON, "outputIPs", outputIPs, "outputPorts", outputPorts})
	}

	if !silenceOutput && checkUpdates {
		if versionName, behind, err := helper.CheckUpdates(ctx); err == nil {
			if behind {
				log.Warn(fmt.Sprintf("Please update to the latest ptForge version. (GitHub: %s, Local: v%s)", versionName, version))
				time.Sleep(time.Millisecond * 500)
			} else {
				log.Info("No updates available.")
			}
		}
	}

	if ptForgeVersion {
		fmt.Printf("ptForge v%s (github.com/sheeptank/ptForge)\n", version)
		os.Exit(0)
	}

	if checkChangelog {
		log.Info("Changelog", fmt.Sprintf("v%s Changes", version), strings.Join(changelog, "\n"))
		log.Info("Exiting")
		os.Exit(0)
	}

	if outputFileDecorator != "" {
		outputName = fmt.Sprintf("%s_%s", outputName, outputFileDecorator)
	}

	if !formatCSV && !formatJSON && !formatSTDOUT {
		log.Warn("Missing some form of output, (--csv/--json/--stdout)")
	}

	if parseBurp != "" {
		log.Info("Parsing Burp XML Report")
		report, err := burp.ParseFile(parseBurp)
		var df *dataframe.DataFrame
		if err != nil {
			log.Error("Failed to parse XML report from Burpsuite. Is it XML?", "error", err)
		}
		if parseJSVulns {
			df, _ = burp.ParseJSVulns(*report)
		} else {
			df, _ = burp.ToDataFrame(*report)
		}
		reporting.HandleReporting(ctx, []dataframe.DataFrame{*df}, outputName)
	}

	if parseNmap != "" {
		log.Info("Parsing an nmap file")
		report, err := nmap.ParseNmap(parseNmap)
		if err != nil {
			log.Error("Failed to parse the Nmap file. Is it XML?", "error", err)
			os.Exit(1)
		}

		var df *dataframe.DataFrame

		df, err = nmap.GetOpenPorts(*report)
		if err != nil {
			log.Error(err)
		}

		if parseNmapScripts {
			df, err = nmap.GetScriptOutput(*report)
			if err != nil {
				log.Error("Failed to get script output from Nmap. Is it XML?", "error", err)
			}
		}
		reporting.HandleReporting(ctx, []dataframe.DataFrame{*df}, outputName)
	}

	if parseNessusFile != "" && !gatherSSH && !gatherSSL {
		log.Info("Beginning Nessus Processing")
		report, err := nessus.ParseFile(parseNessusFile)
		if err != nil {
			log.Error("An error occurred during nessus parsing", "error", err)
			os.Exit(1)
		}
		var plugins []nessus.Plugin

		if reviewSSL {
			if !outputIPs && !outputPorts {
				log.Info("Extracting SSL Related Findings")
			}

			report, err := nessus.ParseFile(parseNessusFile)
			if err != nil {
				log.Error("An error occurred during nessus parsing", "error", err)
				os.Exit(1)
			}
			plugins = nessus.FilterNessusPlugins(report, nessus.NessusSSLPluginList, parseNessusExcludeIDs)
		} else if reviewGeneral {
			plugins = nessus.FilterNessusPlugins(report, nessus.NessusInfoPluginList, parseNessusExcludeIDs)

		} else {
			plugins = nessus.FilterNessusPlugins(report, parseNessusIncludeIDs, parseNessusExcludeIDs)
		}

		log.Infof("%d plugins processed", len(plugins))
		df, _ := nessus.PluginsToDataFrame(plugins, addPO)
		reporting.HandleReporting(ctx, []dataframe.DataFrame{*df}, outputName)
	}

	if (gatherSSH || gatherSSL) && parseEvidenceDirectory == "" {
		report, err := nessus.ParseFile(parseNessusFile)
		if err != nil {
			log.Error("An error occurred during nessus parsing", "error", err)
		}

		var plugins []nessus.Plugin
		var evidenceFile string

		if gatherSSH {
			plugins = nessus.FilterNessusPlugins(report, nessus.NessusSSHDetectionPlugin, "")
			evidenceFile = nmap.GatherSSH(plugins, outputName+"_gatherSSHAlgos")
		} else if gatherSSL {
			plugins = nessus.FilterNessusPlugins(report, nessus.NessusSSLPluginList, "")
			evidenceFile = nmap.GatherSSL(plugins, outputName+"_gatherSSLCiphers")
		}
		if evidenceFile == "" {
			os.Exit(1)
		}

		gatherReport, _ := nmap.ParseNmap(evidenceFile)
		df, err := nmap.GetScriptOutput(*gatherReport)
		if err != nil {
			log.Error(err)
		}
		reporting.HandleReporting(ctx, []dataframe.DataFrame{*df}, outputName)
	}

	if parseEvidenceDirectory != "" {
		var nmapDataFrames []dataframe.DataFrame
		var nessusDataFrames []dataframe.DataFrame
		var burpDataFrames []dataframe.DataFrame

		reports := helper.ParseDir(parseEvidenceDirectory)
		if len(reports) > 0 {
			log.Debug(reports)
		}

		for _, report := range reports {
			switch report := report.(type) {
			case *nmap.NmapXML:
				df, err := nmap.GetScriptOutput(*report)
				if err != nil {
					log.Error("failed to parse nmap file, moving on")
				}
				nmapDataFrames = append(nmapDataFrames, *df)
			case *burp.BurpXML:
				if parseJSVulns {
					df, err := burp.ParseJSVulns(*report)
					if err != nil {
						log.Error("failed to parse burp file, moving on")
					} else {
						burpDataFrames = append(burpDataFrames, *df)
					}
				}
			case *nessus.NessusReport:
				log.Debug("Got an Nessus XML Report")
				if reviewSSL {
					plugins := nessus.FilterNessusPlugins(report, nessus.NessusSSLPluginList, "")
					df, err := nessus.PluginsToDataFrame(plugins, addPO)
					if err != nil {
						log.Error("failed to parse nessus file, moving on")
					}
					nessusDataFrames = append(nessusDataFrames, *df)
				}
				if reviewGeneral {
					plugins := nessus.FilterNessusPlugins(report, nessus.NessusInfoPluginList, "")
					df, err := nessus.PluginsToDataFrame(plugins, addPO)
					if err != nil {
						log.Error("failed to parse nessus file, moving on")
					}
					nessusDataFrames = append(nessusDataFrames, *df)
				}
				if !reviewSSL && !reviewGeneral {
					plugins := nessus.FilterNessusPlugins(report, "", "")
					df, err := nessus.PluginsToDataFrame(plugins, addPO)
					if err != nil {
						log.Error("failed to parse nessus file, moving on")
					}
					nessusDataFrames = append(nessusDataFrames, *df)
				}
				if gatherSSH || gatherSSL {

					var plugins []nessus.Plugin
					var evidenceFile string

					if gatherSSH {
						plugins = nessus.FilterNessusPlugins(report, nessus.NessusSSHDetectionPlugin, "")
						evidenceFile = nmap.GatherSSH(plugins, outputName+"_gatherSSHAlgos")
					} else if gatherSSL {
						plugins = nessus.FilterNessusPlugins(report, nessus.NessusSSLPluginList, "")
						evidenceFile = nmap.GatherSSL(plugins, outputName+"_gatherSSLCiphers")
					}
					if evidenceFile == "" {
						os.Exit(1)
					}

					gatherReport, _ := nmap.ParseNmap(evidenceFile)
					df, err := nmap.GetScriptOutput(*gatherReport)
					if err != nil {
						log.Error(err)
					}
					reporting.HandleReporting(ctx, []dataframe.DataFrame{*df}, outputName)
				}
			default:
				log.Error("unknown file type for report. Ignoring...")
			}
		}

		datasets := []reporting.DataSets{
			{Name: "nessus", Frames: nessusDataFrames},
			{Name: "burp", Frames: burpDataFrames},
			{Name: "nmap", Frames: nmapDataFrames},
		}

		for _, ds := range datasets {
			if len(ds.Frames) > 0 {
				reporting.HandleReporting(ctx, ds.Frames, fmt.Sprintf("%s_evidence_%s", outputName, ds.Name))
			} else {
				log.Debugf("No %sDataFrames to parse", ds.Name)
			}
		}
	}

	if devflag {
		log.Info("There's nothing here")
		log.Debug("Or is there...")
	}

	log.Info("Exiting")
}
