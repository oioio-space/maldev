//go:build windows

package scheduler

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// Task describes a registered scheduled task (returned by List).
type Task struct {
	Name    string
	Path    string
	Enabled bool
}

type triggerKind int

const (
	triggerDaily triggerKind = iota
	triggerLogon
	triggerBoot
	triggerTime
)

// taskTriggerType2 values match the MSDN TASK_TRIGGER_TYPE2 enum.
const (
	taskTriggerTimeID  = 1
	taskTriggerDailyID = 2
	taskTriggerBootID  = 8
	taskTriggerLogonID = 9
)

const (
	taskCreateOrUpdate         = 6
	taskLogonInteractiveToken  = 3
	taskActionExec             = 0
	rpcChangedMode             = 0x80010106
	sFalse                     = 0x00000001 // CoInitializeEx: already initialised on this thread; still needs balancing CoUninitialize.
)

type options struct {
	action        string
	actionArgs    string
	trigger       triggerKind
	dailyInterval int
	triggerTime   time.Time
	hidden        bool
}

// Option configures a scheduled task.
type Option func(*options)

// WithAction sets the executable and optional command-line arguments.
func WithAction(path string, args ...string) Option {
	return func(o *options) {
		o.action = path
		o.actionArgs = strings.Join(args, " ")
	}
}

// WithTriggerLogon fires the task at user logon (requires elevation).
func WithTriggerLogon() Option { return func(o *options) { o.trigger = triggerLogon } }

// WithTriggerStartup fires the task at system startup (requires elevation).
func WithTriggerStartup() Option { return func(o *options) { o.trigger = triggerBoot } }

// WithTriggerDaily fires the task every interval days.
func WithTriggerDaily(interval int) Option {
	return func(o *options) {
		o.trigger = triggerDaily
		o.dailyInterval = interval
	}
}

// WithTriggerTime fires the task once at a specific time.
func WithTriggerTime(t time.Time) Option {
	return func(o *options) {
		o.trigger = triggerTime
		o.triggerTime = t
	}
}

// WithHidden marks the task as hidden in the Task Scheduler UI.
func WithHidden() Option { return func(o *options) { o.hidden = true } }

// Create registers a scheduled task via COM ITaskService. Name must start
// with a backslash: `\TaskName` or `\Folder\TaskName`.
func Create(name string, opts ...Option) error {
	o := &options{trigger: triggerDaily, dailyInterval: 1}
	for _, opt := range opts {
		opt(o)
	}
	if o.action == "" {
		return fmt.Errorf("WithAction is required")
	}

	return withTaskService(func(ts *ole.IDispatch) error {
		root, err := oleFolder(ts, `\`)
		if err != nil {
			return err
		}
		defer root.Release()

		def, err := callDispatch(ts, "NewTask", 0)
		if err != nil {
			return fmt.Errorf("NewTask: %w", err)
		}
		defer def.Release()

		if err := configureDefinition(def, o); err != nil {
			return err
		}

		// oleutil.CallMethod marshals nil → VT_NULL VARIANT; passing an
		// ole.VARIANT directly crashes with "unknown type" inside invoke().
		_, err = oleutil.CallMethod(root, "RegisterTaskDefinition",
			name, def, taskCreateOrUpdate,
			nil, // user (NULL = current)
			nil, // password
			taskLogonInteractiveToken,
			nil, // sddl
		)
		if err != nil {
			return fmt.Errorf("RegisterTaskDefinition: %w", err)
		}
		return nil
	})
}

// Delete removes a scheduled task by name.
func Delete(name string) error {
	folder, leaf := splitTaskName(name)
	return withTaskService(func(ts *ole.IDispatch) error {
		f, err := oleFolder(ts, folder)
		if err != nil {
			return err
		}
		defer f.Release()
		if _, err := oleutil.CallMethod(f, "DeleteTask", leaf, 0); err != nil {
			return fmt.Errorf("DeleteTask(%s): %w", leaf, err)
		}
		return nil
	})
}

// Exists reports whether a task with the given name is registered.
func Exists(name string) (bool, error) {
	folder, leaf := splitTaskName(name)
	var found bool
	err := withTaskService(func(ts *ole.IDispatch) error {
		f, err := oleFolder(ts, folder)
		if err != nil {
			return err
		}
		defer f.Release()
		v, err := oleutil.CallMethod(f, "GetTask", leaf)
		if err != nil {
			return nil
		}
		v.ToIDispatch().Release()
		found = true
		return nil
	})
	return found, err
}

// List enumerates all tasks in the root folder.
func List() ([]Task, error) {
	var result []Task
	err := withTaskService(func(ts *ole.IDispatch) error {
		f, err := oleFolder(ts, `\`)
		if err != nil {
			return err
		}
		defer f.Release()

		col, err := callDispatch(f, "GetTasks", 0)
		if err != nil {
			return fmt.Errorf("GetTasks: %w", err)
		}
		defer col.Release()

		countVar, err := oleutil.GetProperty(col, "Count")
		if err != nil {
			return fmt.Errorf("Count: %w", err)
		}
		count := int(countVar.Val)

		result = make([]Task, 0, count)
		for i := 1; i <= count; i++ {
			itemVar, err := oleutil.CallMethod(col, "Item", i)
			if err != nil {
				continue
			}
			item := itemVar.ToIDispatch()

			nameVar, _ := oleutil.GetProperty(item, "Name")
			pathVar, _ := oleutil.GetProperty(item, "Path")
			enabledVar, _ := oleutil.GetProperty(item, "Enabled")
			result = append(result, Task{
				Name:    nameVar.ToString(),
				Path:    pathVar.ToString(),
				Enabled: enabledVar.Val != 0,
			})
			item.Release()
		}
		return nil
	})
	return result, err
}

// Actions returns the binary paths for every action on a registered
// task that exposes a Path property — in practice exec actions
// (IExecAction). COM/email/message actions have no Path and are
// silently skipped. Returns an empty slice if the task has no such
// actions.
func Actions(name string) ([]string, error) {
	folder, leaf := splitTaskName(name)
	var paths []string
	err := withTaskService(func(ts *ole.IDispatch) error {
		f, err := oleFolder(ts, folder)
		if err != nil {
			return err
		}
		defer f.Release()
		taskVar, err := oleutil.CallMethod(f, "GetTask", leaf)
		if err != nil {
			return fmt.Errorf("GetTask(%s): %w", leaf, err)
		}
		task := taskVar.ToIDispatch()
		defer task.Release()

		def, err := dispatchProperty(task, "Definition")
		if err != nil {
			return err
		}
		defer def.Release()

		acts, err := dispatchProperty(def, "Actions")
		if err != nil {
			return err
		}
		defer acts.Release()

		// IActionCollection is 1-indexed; iterate until Item(i) errors.
		// Avoids relying on the Count property (some task registrations
		// expose it as a weakly-typed VARIANT that go-ole can't unwrap).
		for i := 1; i < 64; i++ {
			itemVar, err := oleutil.CallMethod(acts, "Item", i)
			if err != nil {
				break
			}
			item := itemVar.ToIDispatch()
			// exec actions have Path; COM/email/message don't.
			if p, err := oleutil.GetProperty(item, "Path"); err == nil {
				paths = append(paths, p.ToString())
			}
			item.Release()
		}
		return nil
	})
	return paths, err
}

// Run immediately executes a registered task.
func Run(name string) error {
	folder, leaf := splitTaskName(name)
	return withTaskService(func(ts *ole.IDispatch) error {
		f, err := oleFolder(ts, folder)
		if err != nil {
			return err
		}
		defer f.Release()
		taskVar, err := oleutil.CallMethod(f, "GetTask", leaf)
		if err != nil {
			return fmt.Errorf("GetTask(%s): %w", leaf, err)
		}
		task := taskVar.ToIDispatch()
		defer task.Release()

		runVar, err := oleutil.CallMethod(task, "RunEx", nil, 0, 0, "")
		if err != nil {
			return fmt.Errorf("RunEx: %w", err)
		}
		runVar.Clear() //nolint:errcheck
		return nil
	})
}

// withTaskService initialises COM, connects to Schedule.Service, and hands
// the connected ITaskService IDispatch to fn. All teardown is handled here.
func withTaskService(fn func(*ole.IDispatch) error) error {
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		oe, ok := err.(*ole.OleError)
		if !ok || (oe.Code() != rpcChangedMode && oe.Code() != sFalse) {
			return fmt.Errorf("CoInitializeEx: %w", err)
		}
	}
	defer ole.CoUninitialize()

	svc, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return fmt.Errorf("create Schedule.Service: %w", err)
	}
	defer svc.Release()

	ts, err := svc.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("QueryInterface: %w", err)
	}
	defer ts.Release()

	if _, err := oleutil.CallMethod(ts, "Connect"); err != nil {
		return fmt.Errorf("ITaskService.Connect: %w", err)
	}
	return fn(ts)
}

// configureDefinition populates a task definition IDispatch with settings,
// trigger and action derived from o.
func configureDefinition(def *ole.IDispatch, o *options) error {
	regInfo, err := dispatchProperty(def, "RegistrationInfo")
	if err != nil {
		return err
	}
	defer regInfo.Release()
	oleutil.PutProperty(regInfo, "Description", "System maintenance task") //nolint:errcheck

	settings, err := dispatchProperty(def, "Settings")
	if err != nil {
		return err
	}
	defer settings.Release()
	oleutil.PutProperty(settings, "Hidden", o.hidden)         //nolint:errcheck
	oleutil.PutProperty(settings, "Enabled", true)            //nolint:errcheck
	oleutil.PutProperty(settings, "StartWhenAvailable", true) //nolint:errcheck

	if err := addTrigger(def, o); err != nil {
		return err
	}
	return addAction(def, o)
}

func addTrigger(def *ole.IDispatch, o *options) error {
	triggers, err := dispatchProperty(def, "Triggers")
	if err != nil {
		return err
	}
	defer triggers.Release()

	trig, err := callDispatch(triggers, "Create", triggerTypeID(o.trigger))
	if err != nil {
		return fmt.Errorf("Create trigger: %w", err)
	}
	defer trig.Release()

	// Task Scheduler requires StartBoundary on every trigger type — including
	// DAILY/LOGON/BOOT, where it denotes the earliest activation time.
	// We default to "now" for everything except explicit TIME triggers.
	startBoundary := time.Now().Format("2006-01-02T15:04:05")
	if o.trigger == triggerTime {
		startBoundary = o.triggerTime.Format("2006-01-02T15:04:05")
	}
	oleutil.PutProperty(trig, "StartBoundary", startBoundary) //nolint:errcheck

	if o.trigger == triggerDaily {
		oleutil.PutProperty(trig, "DaysInterval", o.dailyInterval) //nolint:errcheck
	}
	return nil
}

func addAction(def *ole.IDispatch, o *options) error {
	actions, err := dispatchProperty(def, "Actions")
	if err != nil {
		return err
	}
	defer actions.Release()

	act, err := callDispatch(actions, "Create", taskActionExec)
	if err != nil {
		return fmt.Errorf("Create action: %w", err)
	}
	defer act.Release()

	oleutil.PutProperty(act, "Path", o.action)          //nolint:errcheck
	oleutil.PutProperty(act, "Arguments", o.actionArgs) //nolint:errcheck
	return nil
}

func oleFolder(ts *ole.IDispatch, folder string) (*ole.IDispatch, error) {
	v, err := oleutil.CallMethod(ts, "GetFolder", folder)
	if err != nil {
		return nil, fmt.Errorf("GetFolder(%s): %w", folder, err)
	}
	return v.ToIDispatch(), nil
}

func callDispatch(d *ole.IDispatch, method string, args ...any) (*ole.IDispatch, error) {
	v, err := oleutil.CallMethod(d, method, args...)
	if err != nil {
		return nil, err
	}
	return v.ToIDispatch(), nil
}

func dispatchProperty(d *ole.IDispatch, prop string) (*ole.IDispatch, error) {
	v, err := oleutil.GetProperty(d, prop)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", prop, err)
	}
	return v.ToIDispatch(), nil
}

func triggerTypeID(t triggerKind) int {
	switch t {
	case triggerLogon:
		return taskTriggerLogonID
	case triggerBoot:
		return taskTriggerBootID
	case triggerTime:
		return taskTriggerTimeID
	default:
		return taskTriggerDailyID
	}
}

// splitTaskName splits `\Folder\TaskName` into (`\Folder`, `TaskName`).
// Returns (`\`, name) for top-level tasks and bare names without leading slash.
func splitTaskName(name string) (folder, leaf string) {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '\\' {
			if i == 0 {
				return `\`, name[1:]
			}
			return name[:i], name[i+1:]
		}
	}
	return `\`, name
}

// TaskMechanism implements persistence.Mechanism for the Task Scheduler.
type TaskMechanism struct {
	name string
	opts []Option
}

// ScheduledTask returns a persistence.Mechanism backed by the COM Task Scheduler.
func ScheduledTask(name string, opts ...Option) *TaskMechanism {
	return &TaskMechanism{name: name, opts: opts}
}

func (m *TaskMechanism) Name() string     { return "scheduler:" + m.name }
func (m *TaskMechanism) Install() error   { return Create(m.name, m.opts...) }
func (m *TaskMechanism) Uninstall() error { return Delete(m.name) }
func (m *TaskMechanism) Installed() (bool, error) {
	return Exists(m.name)
}
