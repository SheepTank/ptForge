package reporting

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"ptForge/internal/shared/ctxkeys"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/go-gota/gota/dataframe"
)

type DataSets struct {
	Name   string
	Frames []dataframe.DataFrame
}

func HandleReporting(ctx context.Context, dataframes []dataframe.DataFrame, outputName string) {

	var outputIPs bool = ctx.Value(ctxkeys.KeyOutputIPs).(bool)
	var outputPorts bool = ctx.Value(ctxkeys.KeyOutputPorts).(bool)

	if ctx.Value(ctxkeys.KeyFormatSTDOUT).(bool) {
		for _, df := range dataframes {
			if !outputIPs || !outputPorts {
				for i := 0; i < df.Nrow(); i++ {
					for j := 0; j < df.Ncol(); j++ {
						fmt.Print(df.Elem(i, j).String(), " ")
					}
					fmt.Println()
				}
			} else {
				hosts := df.Col("Host").Records()
				ports := df.Col("Port").Records()

				maxlen := len(hosts)
				if maxlen < len(ports) {
					maxlen = len(ports)
				}

				for i := range maxlen {
					var s string = ""
					if outputIPs {
						s = s + hosts[i]
					}
					if outputPorts {
						if outputIPs {
							s = s + ":"
						}
						s = s + ports[i]
					}
					if !strings.HasSuffix(s, ":0") && len(s) > 0 {
						fmt.Println(s)
					}
				}
			}
		}
	}

	df := dataframes[0]
	if len(dataframes) > 1 {
		for _, dataf := range dataframes[1:] {
			df = df.Concat(dataf)
		}
	}

	if ctx.Value(ctxkeys.KeyFormatCSV).(bool) || ctx.Value(ctxkeys.KeyFormatJSON).(bool) {
		log.Infof("Outputting file %s", outputName)
	}

	if ctx.Value(ctxkeys.KeyFormatCSV).(bool) {
		if !strings.HasSuffix(outputName, ".csv") {
			outputName = outputName + ".csv"
		}
		buf := &bytes.Buffer{}
		df.WriteCSV(buf)
		os.WriteFile(outputName, buf.Bytes(), 0755)
	}

	if ctx.Value(ctxkeys.KeyFormatJSON).(bool) {
		if !strings.HasSuffix(outputName, ".json") {
			outputName = outputName + ".json"
		}
		buf := &bytes.Buffer{}
		df.WriteJSON(buf)
		os.WriteFile(outputName, buf.Bytes(), 0755)
	}
}
