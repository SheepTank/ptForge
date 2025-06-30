package helper

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"ptForge/internal/shared/burp"
	"ptForge/internal/shared/nessus"
	"ptForge/internal/shared/nmap"
	"reflect"
	"strings"

	"github.com/charmbracelet/log"
)

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
