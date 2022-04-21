package cpe_ecs

import (
	"context"
	"time"

	"github.com/IrineSistiana/mosdns/v3/dispatcher/handler"
	"github.com/IrineSistiana/mosdns/v3/dispatcher/pkg/pool"
)

const PluginType = "cpe_ecs"

func init() {
	// Register this plugin type with its initialization funcs. So that, this plugin
	// can be configured by user from configuration file.
	handler.RegInitFunc(PluginType, Init, func() interface{} { return new(Args) })

	// You can also register a plugin object directly. (If plugin do not need to configure)
	// Then you can directly use "_sleep_500ms" in configuration file.
	handler.MustRegPlugin(&cpe_ecs{
		BP: handler.NewBP("_cpe_ecs", PluginType),
		d:  time.Millisecond * 500,
	})
}

// Args is the arguments of plugin. It will be decoded from yaml.
// So it is recommended to use `yaml` as struct field's tag.
type Args struct {
	Duration uint `yaml:"duration"` // (milliseconds) duration for sleep.
}

var _ handler.ExecutablePlugin = (*cpe_ecs)(nil)

// cpe_ecs implements handler.ExecutablePlugin.
type cpe_ecs struct {
	*handler.BP
	d time.Duration
}

// Exec implements handler.Executable.
func (s *cpe_ecs) Exec(ctx context.Context, qCtx *handler.Context, next handler.ExecutableChainNode) error {
	if s.d > 0 {
		timer := pool.GetTimer(s.d)
		defer pool.ReleaseTimer(timer)
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Call handler.ExecChainNode() can execute next plugin.
	return handler.ExecChainNode(ctx, qCtx, next)

	// You can control how/when to execute next plugin.
	// For more complex example, see plugin "cache".
}

// Init is a handler.NewPluginFunc.
func Init(bp *handler.BP, args interface{}) (p handler.Plugin, err error) {
	d := args.(*Args).Duration
	return &cpe_ecs{
		BP: bp,
		d:  time.Duration(d) * time.Millisecond,
	}, nil
}
