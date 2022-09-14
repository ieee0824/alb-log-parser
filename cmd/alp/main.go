package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samber/lo"
)

const (
	protocol_type = iota
	request_time
	elb
	client
	target
	request_processing_time
	target_processing_time
	response_processing_time
	elb_status_code
	target_status_code
	received_bytes
	sent_bytes
	request
	user_agent
	ssl_cipher
	ssl_protocol
	target_group_arn
	trace_id
	domain_name
	chosen_cert_arn
	matched_rule_priority
	request_creation_time
	actions_executed
	redirect_url
	lambda_error_reason
	target_port_list
	target_status_code_list
	classification
	classification_reason
)

var tags = []string{
	"protocol_type",
	"request_time",
	"elb",
	"client",
	"target",
	"request_processing_time",
	"target_processing_time",
	"response_processing_time",
	"elb_status_code",
	"target_status_code",
	"received_bytes",
	"sent_bytes",
	"request",
	"user_agent",
	"ssl_cipher",
	"ssl_protocol",
	"target_group_arn",
	"trace_id",
	"domain_name",
	"chosen_cert_arn",
	"matched_rule_priority",
	"request_creation_time",
	"actions_executed",
	"redirect_url",
	"lambda_error_reason",
	"target_port_list",
	"target_status_code_list",
	"classification",
	"classification_reason",
}

type albLog struct {
	ActionsExecuted        string    `json:"actions_executed"`
	ChosenCertArn          string    `json:"chosen_cert_arn"`
	Classification         string    `json:"classification"`
	ClassificationReason   string    `json:"classification_reason"`
	Client                 string    `json:"client"`
	ClientIp               string    `json:"client_ip"`
	ClientPort             int       `json:"client_port"`
	DomainName             string    `json:"domain_name"`
	Elb                    string    `json:"elb"`
	ElbStatusCode          int       `json:"elb_status_code"`
	LambdaErrorReason      string    `json:"lambda_error_reason"`
	MatchedRulePriority    string    `json:"matched_rule_priority"`
	ProtocolType           string    `json:"protocol_type"`
	ReceivedBytes          uint64    `json:"received_bytes"`
	RedirectURL            string    `json:"redirect_url"`
	Request                string    `json:"request"`
	RequestMethod          string    `json:"request_method"`
	RequestURL             string    `json:"request_url"`
	RequestProtocol        string    `json:"request_protocol"`
	RequestCreationTime    time.Time `json:"request_creation_time"`
	RequestProcessingTime  float64   `json:"request_processing_time"`
	ResponseProcessingTime float64   `json:"response_processing_time"`
	SentBytes              uint64    `json:"sent_bytes"`
	SslCipher              string    `json:"ssl_cipher"`
	SslProtocol            string    `json:"ssl_protocol"`
	TargetGroupArn         string    `json:"target_group_arn"`
	Target                 string    `json:"target"`
	TargetIp               string    `json:"target_ip"`
	TargetPort             int       `json:"target_port"`
	TargetPortList         string    `json:"target_port_list"`
	TargetProcessingTime   float64   `json:"target_processing_time"`
	TargetStatusCode       int       `json:"target_status_code"`
	TargetStatusCodeList   string    `json:"target_status_code_list"`
	RequestTime            time.Time `json:"request_time"`
	TraceID                string    `json:"trace_id"`
	UserAgent              string    `json:"user_agent"`
}

type param []string

func getParams(logStr string) []string {
	elems := strings.Split(logStr, " ")

	params := []*param{}
	var buf *param = nil
	for _, elem := range elems {
		if buf == nil && !strings.HasPrefix(elem, "\"") {
			params = append(params, lo.ToPtr(param([]string{elem})))
			continue
		}
		if strings.HasPrefix(elem, "\"") {
			buf = &param{}
		}
		*buf = append(*buf, elem)
		if strings.HasSuffix(elem, "\"") {
			params = append(params, buf)
			buf = nil
		}
	}

	return lo.Map(params, func(p *param, _ int) string {
		return strings.Join(*p, " ")
	})
}

func parseParams(params []string) (*albLog, error) {
	m := map[string]any{}
	lo.ForEach(params, func(s string, i int) {
		switch i {
		case request_processing_time, target_processing_time, response_processing_time:
			f64v, err := strconv.ParseFloat(s, 64)
			if err != nil {
				log.Printf("parse %s error: %s\n", tags[i], err.Error())
				return
			}
			m[tags[i]] = f64v
		case target_status_code, elb_status_code:
			iv, err := strconv.Atoi(s)
			if err != nil {
				log.Printf("parse %s error: %s\n", tags[i], err.Error())
				return
			}
			m[tags[i]] = iv
		case received_bytes, sent_bytes:
			ui64v, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				log.Printf("parse %s error: %s\n", tags[i], err.Error())
				return
			}
			m[tags[i]] = ui64v
		case request:
			m[tags[i]] = strings.ReplaceAll(s, "\"", "")
			params := strings.Split(strings.ReplaceAll(s, "\"", ""), " ")
			if len(params) < 3 {
				return
			}
			m["request_method"] = params[0]
			m["request_url"] = params[1]
			m["request_protocol"] = params[2]
		case client:
			m[tags[i]] = strings.ReplaceAll(s, "\"", "")
			params := strings.Split(strings.ReplaceAll(s, "\"", ""), ":")
			if len(params) < 2 {
				return
			}
			m["client_ip"] = params[0]
			port, err := strconv.Atoi(params[1])
			if err != nil {
				log.Printf("parse %s error: %s\n", tags[i], err.Error())
				return
			}
			m["client_port"] = port
		case target:
			m[tags[i]] = strings.ReplaceAll(s, "\"", "")
			params := strings.Split(strings.ReplaceAll(s, "\"", ""), ":")
			if len(params) < 2 {
				return
			}
			m["target_ip"] = params[0]
			port, err := strconv.Atoi(params[1])
			if err != nil {
				log.Printf("parse %s error: %s\n", tags[i], err.Error())
				return
			}
			m["target_port"] = port
		default:
			m[tags[i]] = strings.ReplaceAll(s, "\"", "")
		}
	})

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(m); err != nil {
		return nil, err
	}

	ret := &albLog{}
	if err := json.NewDecoder(buf).Decode(ret); err != nil {
		return nil, err
	}
	return ret, nil
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		p := getParams(scanner.Text())

		al, err := parseParams(p)
		if err != nil {
			log.Fatalln(err)
		}
		json.NewEncoder(os.Stdout).Encode(al)
	}

	if err := scanner.Err(); err != nil {
		log.Println(err)
	}
}
