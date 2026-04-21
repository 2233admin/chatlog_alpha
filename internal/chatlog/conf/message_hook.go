package conf

const (
	HookNotifyMCP  = "mcp"
	HookNotifyPost = "post"
	HookNotifyBoth = "both"
)

type MessageHook struct {
	Keywords    string `mapstructure:"keywords" json:"keywords"`
	NotifyMode  string `mapstructure:"notify_mode" json:"notify_mode"`
	PostURL     string `mapstructure:"post_url" json:"post_url"`
	BeforeCount int    `mapstructure:"before_count" json:"before_count"`
	AfterCount  int    `mapstructure:"after_count" json:"after_count"`
}
