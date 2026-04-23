//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/sleepmask"
	"github.com/oioio-space/maldev/testutil"
)

func runSelf(cfg demoConfig) error {
	payload := testutil.WindowsSearchableCanary
	size := uintptr(len(payload))
	addr, err := windows.VirtualAlloc(0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("VirtualAlloc: %w", err)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(payload)), payload)
	var old uint32
	if err := windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READ, &old); err != nil {
		return fmt.Errorf("VirtualProtect(RX): %w", err)
	}

	logf(cfg, "allocated canary at 0x%X (RX, %d bytes)", addr, size)

	mask, err := buildMask(cfg, sleepmask.Region{Addr: addr, Size: size})
	if err != nil {
		return err
	}

	stopScan := make(chan struct{})
	if cfg.EnableScanner {
		go runScanner(cfg, []byte("MALDEV_CANARY!!\n"), stopScan)
	}
	defer close(stopScan)

	for cycle := 1; cycle <= cfg.Cycles; cycle++ {
		logf(cfg, "cycle %d/%d begin", cycle, cfg.Cycles)
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Sleep+5*time.Second)
		if err := mask.Sleep(ctx, cfg.Sleep); err != nil {
			cancel()
			return fmt.Errorf("cycle %d: %w", cycle, err)
		}
		cancel()
		logf(cfg, "cycle %d/%d end", cycle, cfg.Cycles)
	}
	return nil
}

func buildMask(cfg demoConfig, region sleepmask.Region) (*sleepmask.Mask, error) {
	var cipher sleepmask.Cipher
	switch cfg.CipherName {
	case "xor":
		cipher = sleepmask.NewXORCipher()
	case "rc4":
		cipher = sleepmask.NewRC4Cipher()
	case "aes":
		cipher = sleepmask.NewAESCTRCipher()
	default:
		return nil, fmt.Errorf("unknown cipher %q", cfg.CipherName)
	}

	var strat sleepmask.Strategy
	switch cfg.StrategyName {
	case "inline":
		strat = &sleepmask.InlineStrategy{UseBusyTrig: cfg.UseBusyTrig}
	case "timerqueue":
		strat = &sleepmask.TimerQueueStrategy{}
	case "ekko":
		strat = &sleepmask.EkkoStrategy{}
		if cfg.CipherName != "rc4" {
			fmt.Fprintln(os.Stderr, "note: EkkoStrategy requires rc4 cipher; overriding")
			cipher = sleepmask.NewRC4Cipher()
		}
	default:
		return nil, fmt.Errorf("unknown strategy %q", cfg.StrategyName)
	}

	return sleepmask.New(region).WithCipher(cipher).WithStrategy(strat), nil
}

func runScanner(cfg demoConfig, marker []byte, stop <-chan struct{}) {
	t := time.NewTicker(cfg.ScannerInterval)
	defer t.Stop()
	start := time.Now()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if addr, ok := testutil.ScanProcessMemory(marker); ok {
				fmt.Printf("[%04dms] scanner HIT at 0x%X\n", elapsedMs(start), addr)
			} else {
				fmt.Printf("[%04dms] scanner MISS\n", elapsedMs(start))
			}
		}
	}
}

func logf(cfg demoConfig, format string, args ...interface{}) {
	if !cfg.Verbose {
		return
	}
	fmt.Printf("[%04dms] "+format+"\n", append([]interface{}{elapsedMs(globalStart)}, args...)...)
}

var globalStart = time.Now()

func elapsedMs(since time.Time) int {
	return int(time.Since(since) / time.Millisecond)
}
