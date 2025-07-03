package helper

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"ptForge/internal/shared/burp"
	"ptForge/internal/shared/ctxkeys"
	"ptForge/internal/shared/nessus"
	"ptForge/internal/shared/nmap"
	"reflect"
	"strings"

	"github.com/charmbracelet/log"
)

// type GithubTags struct {
// 	Tags []Tag
// }

type Tag struct {
	Name    string            `json:"name"`
	Zip     string            `json:"zipball_url"`
	Tar     string            `json:"tarball_url"`
	NodeURL string            `json:"node_id"`
	Commit  map[string]string `json:"commit"`
}

// Check string for contents of a slice, inverse of slices.Contains
func ContainsAny(str string, slice []string) bool {
	for _, sub := range slice {
		if strings.Contains(str, sub) {
			return true
		}
	}
	return false
}

// Tries to return objects for each file.
func ParseDir(directory string) []any {
	info, err := os.Stat(directory)
	if os.IsNotExist(err) {
		log.Debug("helper.ParseDir", "directory", directory, "info", info, "err", err)
		log.Errorf("provided directory (%s) does not exist", directory)
	}

	if !info.IsDir() {
		log.Errorf("provided directory (%s) does not appear to be a directory, is this right?", directory)
	}

	dir, err := os.ReadDir(directory)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	types := []reflect.Type{
		reflect.TypeOf(nmap.NmapXML{}),
		reflect.TypeOf(burp.BurpXML{}),
		reflect.TypeOf(nessus.NessusReport{}),
	}

	reports := []any{}
	for _, file := range dir {
		for _, structType := range types {
			ptr := reflect.New(structType).Interface()

			fd, err := os.ReadFile(filepath.Join(directory, file.Name()))
			if err != nil {
				log.Error(err)
			}
			if err := xml.Unmarshal(fd, &ptr); err == nil {
				reports = append(reports, ptr)
			}

		}
	}
	return reports
}

func CheckUpdates(ctx context.Context) (string, bool, error) {
	log.Debug("Checking for updates")
	resp, err := http.Get("https://api.github.com/repos/sheeptank/ptForge/tags")
	if err != nil {
		if i := ctx.Value(ctxkeys.KeyDebugMode); i.(bool) {
			log.Error("An error occurred during the latest version check.", "error", err)
		}
	}
	var b []Tag
	buf, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(buf, &b)
	if err != nil {
		log.Error("Failed to parse json body from github")
	}

	version := ctx.Value(ctxkeys.KeyVersion)
	if fmt.Sprintf("v%s", version) == b[0].Name {
		return b[0].Name, false, nil
	} else {
		return b[0].Name, true, nil
	}
}
