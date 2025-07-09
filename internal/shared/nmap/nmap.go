package nmap

import (
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"ptForge/internal/shared/nessus"
	"slices"
	"strconv"
	"strings"

	"github.com/charmbracelet/log"
	"github.com/go-gota/gota/dataframe"
)

// region Structs

type NmapHost struct {
	XMLName   xml.Name   `xml:"host"`
	StartTime string     `xml:"starttime,attr"`
	EndTime   string     `xml:"endtime,attr"`
	Status    Status     `xml:"status"`
	Address   []Address  `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     []Port     `xml:"ports>port"`
	Times     Times      `xml:"times"`
}

type Ports struct {
	Ports []Port `xml:"port"`
}

type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   string  `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
	Script   Script  `xml:"script"`
}

type Service struct {
	Name   string `xml:"name,attr"`
	Method string `xml:"method,attr"`
	Conf   string `xml:"conf,attr"`
}

type State struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}

type Script struct {
	ID     string  `xml:"id,attr"`
	Output string  `xml:"output,attr"`
	Tables []Table `xml:"table"`
}

type Table struct {
	Key    string   `xml:"key,attr"`
	Elems  []string `xml:"elem"`
	Tables []Table  `xml:"table"` // allows nesting of <table> inside <table>
}

type Times struct {
	SRTT   string `xml:"srtt,attr"`
	RTTVar string `xml:"rttvar,attr"`
	TO     string `xml:"to,attr"`
}

type Status struct {
	State      string `xml:"state,attr"`
	Reason     string `xml:"reason,attr"`
	ReastonTTL string `xml:"reason_ttl,attr"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type Hostnames struct {
	Hostnames []Hostname `xml:"hostnames"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type NmapXML struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

// endregion

//region Globals

var bad = map[string][]string{
	"ssh2-enum-algos": {
		"3des-cbc",
		"aes128-cbc",
		"aes192-cbc",
		"aes256-cbc",
		"arcforu256",
		"arcfour",
		"arcfour128",
		"arcfour256",
		"blowfish-cbc",
		"cast128-cbc",
		"chacha20-poly1305@libssh.org",
		"chacha20-poly1305@openssh.com",
		"diffie-hellman-group14-sha1",
		"diffie-hellman-group1-sha1",
		"diffie-hellman-group1-sha256",
		"diffie-hellman-group-exchange-sha1",
		"gss-gex-sha1",
		"gss-gex-sha1-",
		"gss-group14-sha1",
		"gss-group14-sha1-",
		"gss-group1-sha1",
		"gss-group1-sha1-",
		"hmac-md5",
		"hmac-md5-96",
		"hmac-md5-96-etm@openssh.com",
		"hmac-md5-etm@openssh.com",
		"hmac-ripemd160",
		"hmac-ripemd160-etm@openssh.com",
		"hmac-ripemd160@openssh.com",
		"hmac-sha1",
		"hmac-sha1-96",
		"hmac-sha1-96-etm@openssh.com",
		"hmac-sha1-etm@openssh.com",
		"hmac-sha2-256-96",
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-96",
		"hmac-sha2-512-etm@openssh.com",
		"rijndael-cbc@lysator.liu.se",
		"ssh-dsa",
		"ssh-dss",
		"ssh-rsa",
		"ssh-rsa1",
		"umac-128-etm@openssh.com",
		"umac-64-etm@openssh.com",
		"umac-64@openssh.com",
	},
	"ssl-enum-ciphers-ciphers": {
		"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
		"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
		"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
		"TLS_DH_anon_WITH_AES_128_CBC_SHA",
		"TLS_DH_anon_WITH_AES_128_CBC_SHA256",
		"TLS_DH_anon_WITH_AES_128_GCM_SHA256",
		"TLS_DH_anon_WITH_AES_256_CBC_SHA",
		"TLS_DH_anon_WITH_AES_256_CBC_SHA256",
		"TLS_DH_anon_WITH_AES_256_GCM_SHA384",
		"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
		"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
		"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
		"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
		"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
		"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
		"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
		"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_DH_anon_WITH_DES_CBC_SHA",
		"TLS_DH_anon_WITH_RC4_128_MD5",
		"TLS_DH_anon_WITH_SEED_CBC_SHA",
		"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
		"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
		"TLS_DH_DSS_WITH_AES_128_CBC_SHA",
		"TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
		"TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
		"TLS_DH_DSS_WITH_AES_256_CBC_SHA",
		"TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
		"TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
		"TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
		"TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
		"TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
		"TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
		"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
		"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
		"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
		"TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_DH_DSS_WITH_DES_CBC_SHA",
		"TLS_DH_DSS_WITH_SEED_CBC_SHA",
		"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
		"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
		"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
		"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
		"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
		"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
		"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
		"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
		"TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
		"TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
		"TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
		"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
		"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
		"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
		"TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_DHE_DSS_WITH_DES_CBC_SHA",
		"TLS_DHE_DSS_WITH_SEED_CBC_SHA",
		"TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
		"TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
		"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
		"TLS_DHE_PSK_WITH_AES_128_CCM",
		"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
		"TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
		"TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
		"TLS_DHE_PSK_WITH_AES_256_CCM",
		"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
		"TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
		"TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
		"TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
		"TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		"TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_DHE_PSK_WITH_NULL_SHA",
		"TLS_DHE_PSK_WITH_NULL_SHA256",
		"TLS_DHE_PSK_WITH_NULL_SHA384",
		"TLS_DHE_PSK_WITH_RC4_128_SHA",
		"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
		"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_DHE_RSA_WITH_AES_128_CCM",
		"TLS_DHE_RSA_WITH_AES_128_CCM_8",
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		"TLS_DHE_RSA_WITH_AES_256_CCM",
		"TLS_DHE_RSA_WITH_AES_256_CCM_8",
		"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
		"TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
		"TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
		"TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
		"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		"TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_DHE_RSA_WITH_DES_CBC_SHA",
		"TLS_DHE_RSA_WITH_SEED_CBC_SHA",
		"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
		"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_DH_RSA_WITH_AES_128_CBC_SHA",
		"TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_DH_RSA_WITH_AES_256_CBC_SHA",
		"TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
		"TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
		"TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
		"TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
		"TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
		"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
		"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		"TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_DH_RSA_WITH_DES_CBC_SHA",
		"TLS_DH_RSA_WITH_SEED_CBC_SHA",
		"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
		"TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
		"TLS_ECDH_anon_WITH_NULL_SHA",
		"TLS_ECDH_anon_WITH_RC4_128_SHA",
		"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
		"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
		"TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
		"TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
		"TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
		"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
		"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_ECDH_ECDSA_WITH_NULL_SHA",
		"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		"TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
		"TLS_ECDHE_ECDSA_WITH_NULL_SHA",
		"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		"TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
		"TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
		"TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
		"TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		"TLS_ECDHE_PSK_WITH_NULL_SHA",
		"TLS_ECDHE_PSK_WITH_NULL_SHA256",
		"TLS_ECDHE_PSK_WITH_NULL_SHA384",
		"TLS_ECDHE_PSK_WITH_RC4_128_SHA",
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		"TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
		"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
		"TLS_ECDHE_RSA_WITH_NULL_SHA",
		"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
		"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
		"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
		"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
		"TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
		"TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
		"TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
		"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
		"TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_ECDH_RSA_WITH_NULL_SHA",
		"TLS_ECDH_RSA_WITH_RC4_128_SHA",
		"TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
		"TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
		"TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
		"TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
		"TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
		"TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
		"TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
		"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
		"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
		"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
		"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
		"TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
		"TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
		"TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
		"TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
		"TLS_KRB5_WITH_DES_CBC_MD5",
		"TLS_KRB5_WITH_DES_CBC_SHA",
		"TLS_KRB5_WITH_IDEA_CBC_MD5",
		"TLS_KRB5_WITH_IDEA_CBC_SHA",
		"TLS_KRB5_WITH_RC4_128_MD5",
		"TLS_KRB5_WITH_RC4_128_SHA",
		"TLS_NULL_WITH_NULL_NULL",
		"TLS_PSK_DHE_WITH_AES_128_CCM_8",
		"TLS_PSK_DHE_WITH_AES_256_CCM_8",
		"TLS_PSK_WITH_3DES_EDE_CBC_SHA",
		"TLS_PSK_WITH_AES_128_CBC_SHA",
		"TLS_PSK_WITH_AES_128_CBC_SHA256",
		"TLS_PSK_WITH_AES_128_CCM",
		"TLS_PSK_WITH_AES_128_CCM_8",
		"TLS_PSK_WITH_AES_128_GCM_SHA256",
		"TLS_PSK_WITH_AES_256_CBC_SHA",
		"TLS_PSK_WITH_AES_256_CBC_SHA384",
		"TLS_PSK_WITH_AES_256_CCM",
		"TLS_PSK_WITH_AES_256_CCM_8",
		"TLS_PSK_WITH_AES_256_GCM_SHA384",
		"TLS_PSK_WITH_ARIA_128_CBC_SHA256",
		"TLS_PSK_WITH_ARIA_128_GCM_SHA256",
		"TLS_PSK_WITH_ARIA_256_CBC_SHA384",
		"TLS_PSK_WITH_ARIA_256_GCM_SHA384",
		"TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		"TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_PSK_WITH_NULL_SHA",
		"TLS_PSK_WITH_NULL_SHA256",
		"TLS_PSK_WITH_NULL_SHA384",
		"TLS_PSK_WITH_RC4_128_SHA",
		"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
		"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
		"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
		"TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
		"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
		"TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
		"TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
		"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
		"TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
		"TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
		"TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
		"TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
		"TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_RSA_PSK_WITH_NULL_SHA",
		"TLS_RSA_PSK_WITH_NULL_SHA256",
		"TLS_RSA_PSK_WITH_NULL_SHA384",
		"TLS_RSA_PSK_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA",
		"TLS_RSA_WITH_AES_128_CBC_SHA256",
		"TLS_RSA_WITH_AES_128_CCM",
		"TLS_RSA_WITH_AES_128_CCM_8",
		"TLS_RSA_WITH_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_AES_256_CBC_SHA",
		"TLS_RSA_WITH_AES_256_CBC_SHA256",
		"TLS_RSA_WITH_AES_256_CCM",
		"TLS_RSA_WITH_AES_256_CCM_8",
		"TLS_RSA_WITH_AES_256_GCM_SHA384",
		"TLS_RSA_WITH_ARIA_128_CBC_SHA256",
		"TLS_RSA_WITH_ARIA_128_GCM_SHA256",
		"TLS_RSA_WITH_ARIA_256_CBC_SHA384",
		"TLS_RSA_WITH_ARIA_256_GCM_SHA384",
		"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
		"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
		"TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
		"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
		"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
		"TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
		"TLS_RSA_WITH_DES_CBC_SHA",
		"TLS_RSA_WITH_IDEA_CBC_SHA",
		"TLS_RSA_WITH_NULL_MD5",
		"TLS_RSA_WITH_NULL_SHA",
		"TLS_RSA_WITH_NULL_SHA256",
		"TLS_RSA_WITH_RC4_128_MD5",
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_SEED_CBC_SHA",
		"TLS_SHA256_SHA256",
		"TLS_SHA384_SHA384",
		"TLS_SM4_CCM_SM3",
		"TLS_SM4_GCM_SM3",
		"TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
		"TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
		"TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
		"TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
		"TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
		"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
		"TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
		"TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
	},
	"ssl-cipher-suits-without-pfs": {
		"_ECDHE_", "_DHE_",
	},
}

var KeyToCSV = map[string]string{
	"kex_algorithms":             "KEX Algorithm",
	"mac_algorithms":             "MAC Algorithm",
	"server_host_key_algorithms": "Server Host Key Algorithm",
	"compression_algorithms":     "Compression Algorithm",
	"encryption_algorithms":      "Encryption Algorithm",
	"TLSv1.0":                    "TLSv1.0 Cipher",
	"TLSv1.1":                    "TLSv1.1 Cipher",
	"TLSv1.2":                    "TLSv1.2 Cipher",
}

var Keys = []string{}

//endregion

func init() {
	for k := range KeyToCSV {
		Keys = append(Keys, k)
	}
}

func ParseNmap(filename string) (*NmapXML, error) {
	fd, err := os.ReadFile(filename)
	if err != nil {
		log.Debug("nmap.ParseNmap", "filename", filename, "Error", err)
		fmt.Println(err)
		os.Exit(1)
	}

	var nmap NmapXML
	err = xml.Unmarshal(fd, &nmap)

	if err != nil {
		log.Debug("nmap.ParseNmap", "filename", filename, "Error", err)
		return nil, err
	}

	return &nmap, nil
}

func GetOpenPorts(nmap NmapXML) (*dataframe.DataFrame, error) {

	hosts := []string{}
	ports := []string{}

	for _, host := range nmap.Hosts {
		var hostaddr string = host.Address[0].Addr
		for _, address := range host.Address {
			log.Debug("nmap.GetOpenPorts", "address", address)
			if address.AddrType == "ipv4" {
				hostaddr = address.Addr
				log.Debug("nmap.GetOpenPorts Resolved to IPv4 Address", "hostaddr", hostaddr)
			}
		}

		for _, port := range host.Ports {
			hosts = append(hosts, hostaddr)
			ports = append(ports, port.PortID)

			log.Debug("nmap.GetOpenPorts Table Generation", "Host", hostaddr, "Port", port.PortID)
		}
	}

	rows := []map[string]any{}
	for i := range hosts {
		rows = append(rows, map[string]any{
			"Host": hosts[i],
			"Port": ports[i],
		})
	}

	df := dataframe.LoadMaps(rows)
	df = df.Select([]string{"Host", "Port"})
	return &df, nil
}

func GetScriptOutput(nmap NmapXML) (*dataframe.DataFrame, error) {
	stats := map[string]int{
		"cbc":    0,
		"cipher": 0,
		"grade":  0,
	}
	grades := []string{"A", "B", "C", "D", "E", "F"}

	hosts := []string{}
	ports := []string{}
	algotypes := []string{}
	algorithm := []string{}

	for _, host := range nmap.Hosts {
		var ipaddress string = host.Address[0].Addr
		for _, address := range host.Address {
			if address.AddrType == "ipv4" {
				ipaddress = address.Addr
				log.Debug("nmap.GetScriptOutput Resolved to IPv4 Address", "ipaddress", ipaddress)
			}
		}
		for _, port := range host.Ports {
			ipaddressport := fmt.Sprintf("%s:%s", ipaddress, port.PortID)
			if port.Script.ID == "ssl-enum-ciphers" {
				for _, cipherSuiteCol := range port.Script.Tables {
					if slices.Contains([]string{"TLSv1.2", "TLSv1.1", "TLSv1.0"}, cipherSuiteCol.Key) { // Only supports 1.0-1.2
						for _, col := range cipherSuiteCol.Tables {
							if col.Key == "ciphers" {
								for _, col := range col.Tables {

									var grade string = "FAIL"
									var iana string
									var typestrength string

									// Establish Filter
									var gradeColId int = -1
									var ianaColId int = -1
									var typestrengthColId int = -1

									for colId, elem := range col.Elems {
										if slices.Contains(grades, elem) && (len(elem) == 1) {
											gradeColId = colId
										} else if !strings.HasPrefix(elem, "TLS_") {
											typestrengthColId = colId
										} else if strings.HasPrefix(elem, "TLS_") {
											ianaColId = colId
										}
									}

									if slices.Contains([]int{gradeColId, ianaColId, typestrengthColId}, -1) {
										log.Error("failed to map nmap script columns correctly. (ssl-enum-ciphers)")
										break
									}

									// Assign column data
									grade = col.Elems[gradeColId]
									iana = col.Elems[ianaColId]
									typestrength = col.Elems[typestrengthColId]

									log.Debug("nmap.GetScriptOutput", "Column Orders", []string{"Grade", grade, "IANA", iana, "Type/Strength", typestrength})

									if grade == "FAIL" {
										log.Error("failed to parse xml file properly: table mapping failure (grade/iana/typestrength)")
										break
									}

									algotype := KeyToCSV[cipherSuiteCol.Key]
									algo := fmt.Sprintf("%s (%s)", iana, typestrength)

									if slices.Contains(bad["ssl-enum-ciphers-ciphers"], iana) {
										stats["cipher"]++
										hosts = append(hosts, ipaddress)
										ports = append(ports, port.PortID)
										algotypes = append(algotypes, algotype)
										algorithm = append(algorithm, algo)
										log.Debug("Reporting cipher based on known-bad list", "iana", iana)
									}
								}
							}
						}
					}
				}
			}
			if port.Script.ID == "ssh2-enum-algos" {
				for _, col := range port.Script.Tables {
					for _, row := range col.Elems {
						if slices.Contains(bad[port.Script.ID], strings.TrimSpace(row)) {
							var fkey string = col.Key
							if slices.Contains(Keys, col.Key) {
								fkey = KeyToCSV[col.Key]
							}

							hosts = append(hosts, ipaddress)
							ports = append(ports, port.PortID)
							algotypes = append(algotypes, fkey)
							algorithm = append(algorithm, row)
							log.Debug("nmap.GetScriptOutput(ssh2-enum-algos) Found a bad algorithm", "Host", ipaddressport, "AlgorithmType", fkey, "Algorithm", strings.TrimSpace(row))
						} else {
							log.Debug("nmap.GetScriptOutput(ssh2-enum-algos): Algorithm is not present in known bad list.", "algo", strings.TrimSpace(row))
						}
					}
				}
			}
		}
	}

	rows := []map[string]any{}
	for i := range hosts {
		rows = append(rows, map[string]any{
			"Host":           hosts[i],
			"Port":           ports[i],
			"Algorithm Type": algotypes[i],
			"Algorithm":      algorithm[i],
		})
	}

	df := dataframe.LoadMaps(rows)
	df = df.Select([]string{"Host", "Port", "Algorithm Type", "Algorithm"})

	return &df, nil
}

func GatherSSH(plugins []nessus.Plugin, outputName string) string {
	hosts := []string{}
	ports := []string{}

	for _, plugin := range plugins {
		strid := strconv.Itoa(plugin.PluginID)
		sport := strconv.Itoa(plugin.Port)
		if slices.Contains(strings.Split(nessus.NessusSSHDetectionPlugin, " "), strid) {
			if !slices.Contains(hosts, plugin.Host) {
				hosts = append(hosts, plugin.Host)
			}
			if !slices.Contains(ports, sport) {
				ports = append(ports, sport)
			}
		}
	}

	if len(hosts) == 0 {
		log.Error("Failed to find hosts to nmap.GatherSSH from.")
		return ""
	}

	tmpHosts, err := os.CreateTemp("", "")
	if err != nil {
		log.Error("Failure during nmap.GatherSSH", "error", err)
		return ""
	}
	buf := []byte(strings.Join(hosts, "\n"))
	tmpHosts.Write(buf)

	if !strings.HasSuffix(outputName, ".xml") {
		outputName = outputName + ".xml"
	}

	log.Debug("Hosts", "hosts", hosts)
	log.Debug("Ports", "ports", ports)

	command := exec.Command(
		"nmap",
		"--script", "ssh2-enum-algos",
		"-p", strings.Join(ports, ","),
		"-iL", tmpHosts.Name(),
		"-oX", outputName,
		"-Pn", "-n",
	)
	command.Env = os.Environ()
	_, err = command.CombinedOutput()

	if err != nil {
		log.Error("Failed to run nmap command", "error", err)
	}

	return outputName
}

func GatherSSL(plugins []nessus.Plugin, outputName string) string {
	hosts := []string{}
	ports := []string{}

	for _, plugin := range plugins {
		strid := strconv.Itoa(plugin.PluginID)
		sport := strconv.Itoa(plugin.Port)
		if slices.Contains(strings.Split(nessus.NessusSSLPluginList, " "), strid) {
			if !slices.Contains(hosts, plugin.Host) {
				hosts = append(hosts, plugin.Host)
			}
			if !slices.Contains(ports, sport) {
				ports = append(ports, sport)
			}
		}
	}

	if len(hosts) == 0 {
		log.Error("Failed to find hosts to nmap.GatherSSL from.")
		return ""
	}

	tmpHosts, err := os.CreateTemp("", "")
	if err != nil {
		log.Error("Failure during nmap.GatherSSL", "error", err)
		return ""
	}
	buf := []byte(strings.Join(hosts, "\n"))
	tmpHosts.Write(buf)

	if !strings.HasSuffix(outputName, ".xml") {
		outputName = outputName + ".xml"
	}

	log.Debug("Hosts", "hosts", hosts)
	log.Debug("Ports", "ports", ports)

	command := exec.Command(
		"nmap",
		"--script", "ssl-enum-ciphers",
		"-p", strings.Join(ports, ","),
		"-iL", tmpHosts.Name(),
		"-oX", outputName,
		"-Pn", "-n",
	)
	command.Env = os.Environ()
	log.Debug(command.Args)
	_, err = command.CombinedOutput()

	if err != nil {
		log.Error("Failed to run nmap command", "error", err)
	}

	return outputName
}
