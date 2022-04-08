package options

type CLIClientOptions struct {
	Config                   string
	Version                  bool
	ServerURL                string
	NumberOfPayloads         int
	Output                   string
	JSON                     bool
	Verbose                  bool
	PollInterval             int
	Persistent               bool
	DNSOnly                  bool
	HTTPOnly                 bool
	SmtpOnly                 bool
	Token                    string
	DisableHTTPFallback      bool
	CorrelationIdLength      int
	CorrelationIdNonceLength int
}
