# Persistence APIs

[<- Back to README](../README.md)

## persistence/registry -- Registry Run/RunOnce Keys

```go
func Set(hive Hive, keyType KeyType, name, value string) error
func Get(hive Hive, keyType KeyType, name string) (string, error)
func Delete(hive Hive, keyType KeyType, name string) error
func Exists(hive Hive, keyType KeyType, name string) (bool, error)
```

**Hive:** `HiveCurrentUser`, `HiveLocalMachine`
**KeyType:** `KeyRun`, `KeyRunOnce`

---

## persistence/startup -- StartUp Folder LNK

```go
func UserDir() (string, error)
func MachineDir() (string, error)
func Install(name, targetPath, args string) error
func InstallMachine(name, targetPath, args string) error
func Remove(name string) error
func RemoveMachine(name string) error
func Exists(name string) bool
```

---

## persistence/scheduler -- Task Scheduler

```go
func Create(ctx context.Context, task *Task) error
func Delete(ctx context.Context, name string) error
func Exists(ctx context.Context, name string) bool
```

**Trigger:** `TriggerLogon`, `TriggerStartup`, `TriggerDaily`

---

## persistence/service -- Windows Service

```go
func Install(cfg *Config) error
func Uninstall(name string) error
func Exists(name string) bool
func IsRunning(name string) bool
func Start(name string) error
func Stop(name string) error
```

**StartType:** `StartAuto`, `StartDelayed`, `StartManual`
