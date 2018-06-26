package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"gopkg.in/alecthomas/kingpin.v2"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type translations map[string]string

var translator = map[string]translations{
	"pxname": {"FRONTEND": "1", "BACKEND": "0"},
	"status": {"UP": "2", "OPEN": "2", "DOWN": "-2", "UP.*": "1", "DOWN.*": "-1", "no check": "0"},
}

var metrics = []string{"qcur", "qmax", "scur", "smax", "slim", "stot", "bin", "bout", "dreq", "dresp", "ereq", "econ", "eresp", "wretr", "wredis", "weight", "act", "bck", "chkfail", "chkdown", "lastchg", "downtime", "qlimit", "throttle", "lbtot", "rate", "rate_lim", "rate_max", "check_duration", "hrsp_1xx", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx", "hrsp_other", "req_rate", "req_rate_max", "req_tot", "cli_abrt", "srv_abrt", "qtime", "ctime", "rtime", "ttime"}

type Client struct {
	host            string
	user            string
	password        string
	tlsVerify       bool
	caCert          string
	tlsClientConfig *tls.Config
}

var (
	host      = kingpin.Flag("host", "HAProxy stats host").Default("http://localhost:9000/stats;csv").String()
	user      = kingpin.Flag("user", "HAProxy stats user").String()
	password  = kingpin.Flag("password", "HAProxy stats pasword").String()
	interval  = kingpin.Flag("interval", "Scrapping interval in seconds").Default("30s").Duration()
	tlsVerify = kingpin.Flag("tls-verify", "Verify TLS certificate").Bool()
	caCert    = kingpin.Flag("cacert", "CA certificate path").String()
)

func main() {
	const version = "0.0.1"
	var metricMap []int
	kingpin.HelpFlag.Short('h')
	kingpin.Version(version)
	kingpin.Parse()
	client := newClient()
	client.getMetrics(time.Now(), &metricMap)
	ticker := time.Tick(*interval)
	for t := range ticker {
		client.getMetrics(t, &metricMap)
	}
}

func newClient() *Client {
	client := &Client{}
	client.host = *host
	client.user = *user
	client.password = *password
	client.tlsVerify = *tlsVerify
	client.caCert = *caCert
	tlsConfig := &tls.Config{}
	tlsConfig.InsecureSkipVerify = *tlsVerify
	// Check if tlsVerify flag is set
	if *tlsVerify == true && *caCert != "" {
		pem, err := ioutil.ReadFile(*caCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read CA file %v: %v\n", *caCert, err)
		}
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(pem)
		tlsConfig.RootCAs = certPool
	}
	client.tlsClientConfig = tlsConfig
	return client
}

func (c *Client) getMetrics(t time.Time, metricMap *[]int) {
	req, _ := http.NewRequest("GET", c.host, nil)
	req.SetBasicAuth(c.user, c.password)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting metrics: %v\n", err)
		return
	}
	if resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "Error getting metrics: %v\n", resp.Status)
		return
	}
	defer resp.Body.Close()
	u, _ := url.Parse(c.host)
	parseMetrics(resp.Body, t, u.Host, metricMap)
}

// Tests wether a string is contained in a slice of strings or not
// Comparison is case sensitive
func inSlice(slice []string, s string) (int, error) {
	for p, v := range slice {
		if v == s {
			return p, nil
			break
		}
	}
	return 0, fmt.Errorf("%v string not found in slice", s)
}

func parseMetrics(body io.Reader, t time.Time, hostPort string, metricMap *[]int) {
	var mtrBuffer bytes.Buffer
	var translatorMap = make(map[int]translations)
	reader := csv.NewReader(body)
	headers, err := reader.Read()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading metrics: %v\n", err)
	}
	if len(*metricMap) == 0 {
		for _, m := range metrics {
			pos, err := inSlice(headers, m)
			if err == nil {
				*metricMap = append(*metricMap, pos)
			}
		}
	}
	// Iterate lines
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		}
		// Clean buffer
		mtrBuffer.Reset()
		for k, v := range translatorMap {
			for orig, trans := range v {
				if line[k] == orig {
					line[k] = trans
					break
				}
			}
		}
		// Get Metrics
		for _, pos := range *metricMap {
			if line[pos] == "" {
				line[pos] = "0"
			}
			mtrBuffer.WriteString(fmt.Sprintf(":%v", line[pos]))
		}
		pxname := strings.Replace(line[0], "-", "_", -1)
		svname := strings.ToLower(strings.Replace(line[1], "-", "_", -1))
		fmt.Fprintf(os.Stdout, "PUTVAL %v/haproxy/haproxy-%v@%v interval=%v %v%v\n", hostPort, pxname, svname, interval.Seconds(), t.Unix(), mtrBuffer.String())
	}
}
