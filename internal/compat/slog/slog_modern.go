//go:build go1.21

package slog

import stdslog "log/slog"

type (
	Logger         = stdslog.Logger
	Handler        = stdslog.Handler
	Record         = stdslog.Record
	Attr           = stdslog.Attr
	Value          = stdslog.Value
	Kind           = stdslog.Kind
	Level          = stdslog.Level
	LevelVar       = stdslog.LevelVar
	Leveler        = stdslog.Leveler
	HandlerOptions = stdslog.HandlerOptions
	Source         = stdslog.Source
)

var (
	New            = stdslog.New
	NewTextHandler = stdslog.NewTextHandler
	NewJSONHandler = stdslog.NewJSONHandler
	Default        = stdslog.Default
	SetDefault     = stdslog.SetDefault
	With           = stdslog.With
	Debug          = stdslog.Debug
	Info           = stdslog.Info
	Warn           = stdslog.Warn
	Error          = stdslog.Error
	String         = stdslog.String
	Int            = stdslog.Int
	Int64          = stdslog.Int64
	Bool           = stdslog.Bool
	Any            = stdslog.Any
	Float64        = stdslog.Float64
	Duration       = stdslog.Duration
	Time           = stdslog.Time
	Group          = stdslog.Group
	StringValue    = stdslog.StringValue
	IntValue       = stdslog.IntValue
	Int64Value     = stdslog.Int64Value
	AnyValue       = stdslog.AnyValue
	BoolValue      = stdslog.BoolValue
	Float64Value   = stdslog.Float64Value
	TimeValue      = stdslog.TimeValue
	DurationValue  = stdslog.DurationValue
	GroupValue     = stdslog.GroupValue
)

const (
	LevelDebug = stdslog.LevelDebug
	LevelInfo  = stdslog.LevelInfo
	LevelWarn  = stdslog.LevelWarn
	LevelError = stdslog.LevelError
)

const (
	KindAny      = stdslog.KindAny
	KindBool     = stdslog.KindBool
	KindDuration = stdslog.KindDuration
	KindFloat64  = stdslog.KindFloat64
	KindInt64    = stdslog.KindInt64
	KindString   = stdslog.KindString
	KindTime     = stdslog.KindTime
	KindUint64   = stdslog.KindUint64
	KindGroup    = stdslog.KindGroup
	KindLogValuer = stdslog.KindLogValuer
)
