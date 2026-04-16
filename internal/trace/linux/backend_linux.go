//go:build linux

package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/pidtrail/pidtrail/internal/config"
	"github.com/pidtrail/pidtrail/internal/event"
	"github.com/pidtrail/pidtrail/internal/procfs"
)

const (
	rawEventSize = 192

	rawKindConnect = 1
	rawKindAccept  = 2
	rawKindClose   = 3
	rawKindExec    = 4
	rawKindOpen    = 5
	rawKindClone   = 6
	rawKindExit    = 7

	pathOffset = 68
	pathSize   = 120
)

type Backend struct{}

type collector struct {
	eventsPerf   *ebpf.Map
	targets      *ebpf.Map
	connectState *ebpf.Map
	acceptState  *ebpf.Map
	reader       *perf.Reader
	programs     []*ebpf.Program
	links        []link.Link
}

type targetManager struct {
	targetMap *ebpf.Map
	sink      chan<- event.Event

	mu      sync.Mutex
	tracked map[uint32]struct{}
	roots   map[uint32]struct{}
}

func New() *Backend {
	return &Backend{}
}

func (b *Backend) Run(ctx context.Context, cfg config.Options, sink chan<- event.Event) error {
	defer close(sink)

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}
	col, err := newCollector()
	if err != nil {
		return err
	}
	defer col.Close()

	tm := &targetManager{
		targetMap: col.targets,
		sink:      sink,
		tracked:   make(map[uint32]struct{}),
		roots:     make(map[uint32]struct{}),
	}
	if err := tm.seed(ctx, cfg); err != nil {
		return err
	}

	sink <- event.NewDiagnostic("linux runtime investigation initialized with eBPF tracepoints")
	sink <- event.NewDiagnostic("capture surface: process lifecycle, file opens, and network activity metadata")

	go func() {
		<-ctx.Done()
		_ = col.reader.Close()
	}()

	for {
		record, err := col.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read perf event: %w", err)
		}
		if record.LostSamples != 0 {
			sink <- event.NewDiagnostic(fmt.Sprintf("lost %d kernel samples", record.LostSamples))
			continue
		}
		ev, err := decodeRawEvent(record.RawSample)
		if err != nil {
			sink <- event.NewDiagnostic("decode failure: " + err.Error())
			continue
		}
		switch ev.Kind {
		case event.KindNetwork:
			if ev.Operation == "close" {
				if !enrichSocket(&ev) {
					continue
				}
			} else {
				enrichSocket(&ev)
			}
		case event.KindProcess:
			if ev.Operation == "clone" && ev.ChildPID > 0 {
				if err := tm.addDescendant(ev.ChildPID); err != nil {
					sink <- event.NewDiagnostic(fmt.Sprintf("failed to track child pid %d: %v", ev.ChildPID, err))
				}
			}
			if ev.Operation == "exit" && ev.PID > 0 {
				_ = tm.remove(ev.PID)
			}
		}
		sink <- ev
	}
}

func (b *Backend) Diagnose(ctx context.Context, cfg config.Options) ([]event.Event, error) {
	tracefs := "/sys/kernel/tracing"
	if _, err := os.Stat(tracefs); err != nil {
		tracefs = "/sys/kernel/debug/tracing"
	}
	events := []event.Event{
		event.NewDiagnostic("platform: linux"),
		event.NewDiagnostic("tool scope: process/file/network timeline capture"),
		event.NewDiagnostic("tracefs path: " + tracefs),
	}
	if os.Geteuid() != 0 && cfg.RequireRootCheck {
		events = append(events, event.NewDiagnostic("effective uid is not 0; tracepoint attach is likely to fail"))
	}
	for _, candidate := range []string{
		filepath.Join(tracefs, "events", "syscalls"),
		filepath.Join(tracefs, "events", "sched"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			events = append(events, event.NewDiagnostic("found tracing path: "+candidate))
		}
	}
	if len(cfg.Command) > 0 {
		events = append(events, event.NewDiagnostic("command mode: supported on Linux using direct exec"))
	}
	return events, nil
}

func newCollector() (*collector, error) {
	eventsPerf, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "pt_events",
		Type: ebpf.PerfEventArray,
	})
	if err != nil {
		return nil, fmt.Errorf("create perf map: %w", err)
	}
	targets, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "pt_targets",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 8192,
	})
	if err != nil {
		eventsPerf.Close()
		return nil, fmt.Errorf("create target map: %w", err)
	}
	connectState, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "pt_conn",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  24,
		MaxEntries: 8192,
	})
	if err != nil {
		eventsPerf.Close()
		targets.Close()
		return nil, fmt.Errorf("create connect state map: %w", err)
	}
	acceptState, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "pt_acc",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 8192,
	})
	if err != nil {
		eventsPerf.Close()
		targets.Close()
		connectState.Close()
		return nil, fmt.Errorf("create accept state map: %w", err)
	}
	reader, err := perf.NewReader(eventsPerf, os.Getpagesize()*16)
	if err != nil {
		eventsPerf.Close()
		targets.Close()
		connectState.Close()
		acceptState.Close()
		return nil, fmt.Errorf("create perf reader: %w", err)
	}

	specs := []*ebpf.ProgramSpec{
		enterConnectSpec(targets, connectState),
		exitConnectSpec(eventsPerf, connectState),
		enterAcceptSpec(targets, acceptState),
		exitAcceptSpec(eventsPerf, acceptState),
		closeSpec(eventsPerf, targets),
		execSpec(eventsPerf, targets),
		openSpec(eventsPerf, targets, "pt_open", 24),
		openSpec(eventsPerf, targets, "pt_open2", 24),
		cloneExitSpec(eventsPerf, targets, "pt_clone"),
		cloneExitSpec(eventsPerf, targets, "pt_fork"),
		cloneExitSpec(eventsPerf, targets, "pt_vfork"),
		cloneExitSpec(eventsPerf, targets, "pt_clone3"),
		exitSpec(eventsPerf, targets, "pt_exit"),
		exitSpec(eventsPerf, targets, "pt_exitg"),
	}
	programs := make([]*ebpf.Program, 0, len(specs))
	for _, spec := range specs {
		prog, err := ebpf.NewProgram(spec)
		if err != nil {
			reader.Close()
			eventsPerf.Close()
			targets.Close()
			connectState.Close()
			acceptState.Close()
			for _, loaded := range programs {
				loaded.Close()
			}
			return nil, fmt.Errorf("load program %s: %w", spec.Name, err)
		}
		programs = append(programs, prog)
	}

	attachments := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{"syscalls", "sys_enter_connect", programs[0]},
		{"syscalls", "sys_exit_connect", programs[1]},
		{"syscalls", "sys_enter_accept", programs[2]},
		{"syscalls", "sys_exit_accept", programs[3]},
		{"syscalls", "sys_enter_accept4", programs[2]},
		{"syscalls", "sys_exit_accept4", programs[3]},
		{"syscalls", "sys_enter_close", programs[4]},
		{"syscalls", "sys_enter_execve", programs[5]},
		{"syscalls", "sys_enter_openat", programs[6]},
		{"syscalls", "sys_enter_openat2", programs[7]},
		{"syscalls", "sys_exit_clone", programs[8]},
		{"syscalls", "sys_exit_fork", programs[9]},
		{"syscalls", "sys_exit_vfork", programs[10]},
		{"syscalls", "sys_exit_clone3", programs[11]},
		{"syscalls", "sys_enter_exit", programs[12]},
		{"syscalls", "sys_enter_exit_group", programs[13]},
	}
	linksOut := make([]link.Link, 0, len(attachments))
	for _, att := range attachments {
		tp, err := link.Tracepoint(att.group, att.name, att.prog, nil)
		if err != nil {
			reader.Close()
			eventsPerf.Close()
			targets.Close()
			connectState.Close()
			acceptState.Close()
			for _, loaded := range programs {
				loaded.Close()
			}
			for _, l := range linksOut {
				l.Close()
			}
			return nil, fmt.Errorf("attach %s/%s: %w", att.group, att.name, err)
		}
		linksOut = append(linksOut, tp)
	}

	return &collector{
		eventsPerf:   eventsPerf,
		targets:      targets,
		connectState: connectState,
		acceptState:  acceptState,
		reader:       reader,
		programs:     programs,
		links:        linksOut,
	}, nil
}

func (c *collector) Close() error {
	for _, l := range c.links {
		_ = l.Close()
	}
	for _, prog := range c.programs {
		_ = prog.Close()
	}
	if c.reader != nil {
		_ = c.reader.Close()
	}
	if c.acceptState != nil {
		_ = c.acceptState.Close()
	}
	if c.connectState != nil {
		_ = c.connectState.Close()
	}
	if c.targets != nil {
		_ = c.targets.Close()
	}
	if c.eventsPerf != nil {
		_ = c.eventsPerf.Close()
	}
	return nil
}

func (tm *targetManager) seed(ctx context.Context, cfg config.Options) error {
	switch {
	case cfg.PID > 0:
		return tm.addRoot(cfg.PID)
	case cfg.Process != "":
		if err := tm.refreshProcessRoots(cfg.Process); err != nil {
			return err
		}
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := tm.refreshProcessRoots(cfg.Process); err != nil {
						tm.sink <- event.NewDiagnostic("process scan failed: " + err.Error())
					}
				}
			}
		}()
		return nil
	case len(cfg.Command) > 0:
		cmd := exec.CommandContext(ctx, cfg.Command[0], cfg.Command[1:]...)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start command: %w", err)
		}
		if err := tm.addRoot(cmd.Process.Pid); err != nil {
			return err
		}
		tm.sink <- event.NewDiagnostic(fmt.Sprintf("launched command pid=%d: %s", cmd.Process.Pid, strings.Join(cfg.Command, " ")))
		go func() {
			err := cmd.Wait()
			if err != nil {
				tm.sink <- event.NewDiagnostic("launched command exited with error: " + err.Error())
				return
			}
			tm.sink <- event.NewDiagnostic(fmt.Sprintf("launched command exited: pid=%d", cmd.Process.Pid))
		}()
		return nil
	default:
		return fmt.Errorf("no trace scope configured")
	}
}

func (tm *targetManager) refreshProcessRoots(name string) error {
	pids, err := procfs.FindPIDsByComm(name)
	if err != nil {
		return err
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	nextRoots := make(map[uint32]struct{}, len(pids))
	for _, pid := range pids {
		nextRoots[uint32(pid)] = struct{}{}
	}
	for root := range tm.roots {
		if _, ok := nextRoots[root]; ok {
			continue
		}
		if _, tracked := tm.tracked[root]; tracked {
			delete(tm.tracked, root)
			_ = tm.targetMap.Delete(root)
		}
	}
	for root := range nextRoots {
		if _, ok := tm.tracked[root]; !ok {
			var one uint8 = 1
			if err := tm.targetMap.Update(root, one, ebpf.UpdateAny); err != nil {
				return err
			}
			tm.tracked[root] = struct{}{}
		}
	}
	tm.roots = nextRoots
	if len(nextRoots) == 0 {
		tm.sink <- event.NewDiagnostic(fmt.Sprintf("waiting for a process named %q", name))
	}
	return nil
}

func (tm *targetManager) addRoot(pid int) error {
	return tm.addPID(uint32(pid), true)
}

func (tm *targetManager) addDescendant(pid int) error {
	return tm.addPID(uint32(pid), false)
}

func (tm *targetManager) addPID(pid uint32, root bool) error {
	if pid == 0 {
		return nil
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if _, ok := tm.tracked[pid]; ok {
		if root {
			tm.roots[pid] = struct{}{}
		}
		return nil
	}
	var one uint8 = 1
	if err := tm.targetMap.Update(pid, one, ebpf.UpdateAny); err != nil {
		return err
	}
	tm.tracked[pid] = struct{}{}
	if root {
		tm.roots[pid] = struct{}{}
	}
	return nil
}

func (tm *targetManager) remove(pid int) error {
	if pid <= 0 {
		return nil
	}
	key := uint32(pid)
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.roots, key)
	if _, ok := tm.tracked[key]; !ok {
		return nil
	}
	delete(tm.tracked, key)
	return tm.targetMap.Delete(key)
}

func decodeRawEvent(raw []byte) (event.Event, error) {
	if len(raw) < rawEventSize {
		return event.Event{}, fmt.Errorf("short sample: %d", len(raw))
	}
	kind := binary.LittleEndian.Uint32(raw[8:12])
	flags := binary.LittleEndian.Uint32(raw[12:16])
	pid := int(binary.LittleEndian.Uint32(raw[16:20]))
	tid := int(binary.LittleEndian.Uint32(raw[20:24]))
	fd := int(int32(binary.LittleEndian.Uint32(raw[24:28])))
	aux := int(binary.LittleEndian.Uint32(raw[28:32]))
	family := binary.LittleEndian.Uint16(raw[32:34])
	port := binary.BigEndian.Uint16(raw[34:36])
	comm := strings.TrimRight(string(raw[52:68]), "\x00")
	path := strings.TrimRight(string(raw[pathOffset:pathOffset+pathSize]), "\x00")

	ev := event.Event{
		Time:   time.Unix(0, int64(binary.LittleEndian.Uint64(raw[:8]))).UTC(),
		Source: event.SourceKernelMetadata,
		PID:    pid,
		TID:    tid,
		Comm:   comm,
		FD:     fd,
		Path:   path,
	}

	switch kind {
	case rawKindConnect:
		ev.Kind = event.KindNetwork
		ev.Operation = "connect"
		ev.Direction = event.DirectionOutbound
	case rawKindAccept:
		ev.Kind = event.KindNetwork
		ev.Operation = "accept"
		ev.Direction = event.DirectionInbound
	case rawKindClose:
		ev.Kind = event.KindNetwork
		ev.Operation = "close"
	case rawKindExec:
		ev.Kind = event.KindProcess
		ev.Operation = "exec"
	case rawKindOpen:
		ev.Kind = event.KindFile
		ev.Operation = "open"
	case rawKindClone:
		ev.Kind = event.KindProcess
		ev.Operation = "clone"
		ev.ChildPID = aux
		ev.ParentPID = pid
	case rawKindExit:
		ev.Kind = event.KindProcess
		ev.Operation = "exit"
		ev.ExitCode = aux
	default:
		return event.Event{}, fmt.Errorf("unknown raw kind %d", kind)
	}

	if ev.Kind == event.KindNetwork {
		switch flags {
		case 1:
			ev.Direction = event.DirectionOutbound
		case 2:
			ev.Direction = event.DirectionInbound
		}
		switch family {
		case 2:
			ev.DstAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{raw[36], raw[37], raw[38], raw[39]}), port).String()
		case 10:
			var addr [16]byte
			copy(addr[:], raw[36:52])
			ev.DstAddr = netip.AddrPortFrom(netip.AddrFrom16(addr), port).String()
		}
	}
	return ev, nil
}

func enrichSocket(ev *event.Event) bool {
	if ev.PID <= 0 || ev.FD < 0 {
		return false
	}
	info, err := procfs.ResolveSocket(ev.PID, ev.FD)
	if err != nil {
		return false
	}
	ev.Protocol = info.Network
	ev.SrcAddr = info.Local
	if ev.Direction == event.DirectionOutbound {
		if ev.DstAddr == "" {
			ev.DstAddr = info.Remote
		}
	} else {
		if ev.DstAddr == "" {
			ev.DstAddr = info.Remote
		}
	}
	return true
}

func programSpec(name string, insns asm.Instructions) *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name:         name,
		Type:         ebpf.TracePoint,
		License:      "GPL",
		Instructions: insns,
	}
}

func gatedEventPrefix(targets *ebpf.Map) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R9, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.RSh.Imm(asm.R6, 32),
		asm.StoreMem(asm.RFP, -12, asm.R6, asm.Word),
		asm.LoadMapPtr(asm.R1, targets.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -12),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
	}
}

func zeroRawEvent(offset int16) asm.Instructions {
	return asm.Instructions{
		asm.StoreImm(asm.RFP, offset, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+8, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+16, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+24, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+32, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+40, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+48, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+56, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+64, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+72, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+80, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+88, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+96, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+104, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+112, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+120, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+128, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+136, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+144, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+152, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+160, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+168, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+176, 0, asm.DWord),
		asm.StoreImm(asm.RFP, offset+184, 0, asm.DWord),
	}
}

func fillCommonEvent(kind uint32, flags uint32, rawOffset int16) asm.Instructions {
	return asm.Instructions{
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, rawOffset, asm.R0, asm.DWord),
		asm.StoreImm(asm.RFP, rawOffset+8, int64(kind), asm.Word),
		asm.StoreImm(asm.RFP, rawOffset+12, int64(flags), asm.Word),
		asm.Mov.Reg(asm.R4, asm.R7),
		asm.RSh.Imm(asm.R4, 32),
		asm.StoreMem(asm.RFP, rawOffset+16, asm.R4, asm.Word),
		asm.StoreMem(asm.RFP, rawOffset+20, asm.R7, asm.Word),
	}
}

func emitEvent(eventsPerf *ebpf.Map, rawOffset int16) asm.Instructions {
	return asm.Instructions{
		asm.Mov.Reg(asm.R1, asm.R9),
		asm.LoadMapPtr(asm.R2, eventsPerf.FD()),
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, int32(rawOffset)),
		asm.Mov.Imm(asm.R5, rawEventSize),
		asm.FnPerfEventOutput.Call(),
	}
}

func enterConnectSpec(targets, connectState *ebpf.Map) *ebpf.ProgramSpec {
	ins := gatedEventPrefix(targets)
	ins = append(ins,
		asm.StoreMem(asm.RFP, -8, asm.R7, asm.DWord),
		asm.StoreImm(asm.RFP, -48, 0, asm.DWord),
		asm.StoreImm(asm.RFP, -40, 0, asm.DWord),
		asm.StoreImm(asm.RFP, -32, 0, asm.DWord),
		asm.LoadMem(asm.R2, asm.R9, 16, asm.DWord),
		asm.StoreMem(asm.RFP, -48, asm.R2, asm.Word),
		asm.LoadMem(asm.R3, asm.R9, 24, asm.DWord),
		asm.Mov.Reg(asm.R8, asm.R3),
		asm.JEq.Imm(asm.R8, 0, "update"),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -44),
		asm.Mov.Imm(asm.R2, 2),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeReadUser.Call(),
		asm.LoadMem(asm.R4, asm.RFP, -44, asm.Half),
		asm.JEq.Imm(asm.R4, 2, "ipv4"),
		asm.JEq.Imm(asm.R4, 10, "ipv6"),
		asm.Ja.Label("update"),
		asm.Mov.Reg(asm.R1, asm.RFP).WithSymbol("ipv4"),
		asm.Add.Imm(asm.R1, -42),
		asm.Mov.Imm(asm.R2, 2),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.Add.Imm(asm.R3, 2),
		asm.FnProbeReadUser.Call(),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -40),
		asm.Mov.Imm(asm.R2, 4),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.Add.Imm(asm.R3, 4),
		asm.FnProbeReadUser.Call(),
		asm.Ja.Label("update"),
		asm.Mov.Reg(asm.R1, asm.RFP).WithSymbol("ipv6"),
		asm.Add.Imm(asm.R1, -42),
		asm.Mov.Imm(asm.R2, 2),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.Add.Imm(asm.R3, 2),
		asm.FnProbeReadUser.Call(),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -40),
		asm.Mov.Imm(asm.R2, 16),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.Add.Imm(asm.R3, 8),
		asm.FnProbeReadUser.Call(),
		asm.LoadMapPtr(asm.R1, connectState.FD()).WithSymbol("update"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -48),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return programSpec("pt_en_conn", ins)
}

func exitConnectSpec(eventsPerf, connectState *ebpf.Map) *ebpf.ProgramSpec {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R9, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.StoreMem(asm.RFP, -8, asm.R7, asm.DWord),
		asm.LoadMem(asm.R8, asm.R9, 16, asm.DWord),
		asm.LoadMapPtr(asm.R1, connectState.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.JNE.Imm(asm.R8, 0, "cleanup"),
	}
	ins = append(ins, zeroRawEvent(-224)...)
	ins = append(ins, fillCommonEvent(rawKindConnect, 1, -224)...)
	ins = append(ins,
		asm.LoadMem(asm.R4, asm.R6, 0, asm.Word),
		asm.StoreMem(asm.RFP, -200, asm.R4, asm.Word),
		asm.LoadMem(asm.R4, asm.R6, 4, asm.Half),
		asm.StoreMem(asm.RFP, -192, asm.R4, asm.Half),
		asm.LoadMem(asm.R4, asm.R6, 6, asm.Half),
		asm.StoreMem(asm.RFP, -190, asm.R4, asm.Half),
		asm.LoadMem(asm.R4, asm.R6, 8, asm.DWord),
		asm.StoreMem(asm.RFP, -188, asm.R4, asm.DWord),
		asm.LoadMem(asm.R4, asm.R6, 16, asm.DWord),
		asm.StoreMem(asm.RFP, -180, asm.R4, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -172),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
	)
	ins = append(ins, emitEvent(eventsPerf, -224)...)
	ins = append(ins,
		asm.LoadMapPtr(asm.R1, connectState.FD()).WithSymbol("cleanup"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return programSpec("pt_ex_conn", ins)
}

func enterAcceptSpec(targets, acceptState *ebpf.Map) *ebpf.ProgramSpec {
	ins := gatedEventPrefix(targets)
	ins = append(ins,
		asm.StoreMem(asm.RFP, -8, asm.R7, asm.DWord),
		asm.StoreImm(asm.RFP, -16, 0, asm.DWord),
		asm.LoadMem(asm.R2, asm.R9, 24, asm.DWord),
		asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord),
		asm.LoadMapPtr(asm.R1, acceptState.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return programSpec("pt_en_acc", ins)
}

func exitAcceptSpec(eventsPerf, acceptState *ebpf.Map) *ebpf.ProgramSpec {
	ins := asm.Instructions{
		asm.Mov.Reg(asm.R9, asm.R1),
		asm.FnGetCurrentPidTgid.Call(),
		asm.Mov.Reg(asm.R7, asm.R0),
		asm.StoreMem(asm.RFP, -8, asm.R7, asm.DWord),
		asm.LoadMem(asm.R8, asm.R9, 16, asm.DWord),
		asm.LoadMapPtr(asm.R1, acceptState.FD()),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.JSLT.Imm(asm.R8, 0, "cleanup"),
	}
	ins = append(ins, zeroRawEvent(-224)...)
	ins = append(ins, fillCommonEvent(rawKindAccept, 2, -224)...)
	ins = append(ins,
		asm.StoreMem(asm.RFP, -200, asm.R8, asm.Word),
		asm.LoadMem(asm.R5, asm.R6, 0, asm.DWord),
		asm.JEq.Imm(asm.R5, 0, "skip_sockaddr"),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -192),
		asm.Mov.Imm(asm.R2, 2),
		asm.Mov.Reg(asm.R3, asm.R5),
		asm.FnProbeReadUser.Call(),
		asm.LoadMem(asm.R4, asm.RFP, -192, asm.Half),
		asm.JEq.Imm(asm.R4, 2, "acc_ipv4"),
		asm.JEq.Imm(asm.R4, 10, "acc_ipv6"),
		asm.Ja.Label("skip_sockaddr"),
		asm.Mov.Reg(asm.R1, asm.RFP).WithSymbol("acc_ipv4"),
		asm.Add.Imm(asm.R1, -190),
		asm.Mov.Imm(asm.R2, 2),
		asm.Mov.Reg(asm.R3, asm.R5),
		asm.Add.Imm(asm.R3, 2),
		asm.FnProbeReadUser.Call(),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -188),
		asm.Mov.Imm(asm.R2, 4),
		asm.Mov.Reg(asm.R3, asm.R5),
		asm.Add.Imm(asm.R3, 4),
		asm.FnProbeReadUser.Call(),
		asm.Ja.Label("skip_sockaddr"),
		asm.Mov.Reg(asm.R1, asm.RFP).WithSymbol("acc_ipv6"),
		asm.Add.Imm(asm.R1, -190),
		asm.Mov.Imm(asm.R2, 2),
		asm.Mov.Reg(asm.R3, asm.R5),
		asm.Add.Imm(asm.R3, 2),
		asm.FnProbeReadUser.Call(),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -188),
		asm.Mov.Imm(asm.R2, 16),
		asm.Mov.Reg(asm.R3, asm.R5),
		asm.Add.Imm(asm.R3, 8),
		asm.FnProbeReadUser.Call(),
		asm.Mov.Reg(asm.R1, asm.RFP).WithSymbol("skip_sockaddr"),
		asm.Add.Imm(asm.R1, -172),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
	)
	ins = append(ins, emitEvent(eventsPerf, -224)...)
	ins = append(ins,
		asm.LoadMapPtr(asm.R1, acceptState.FD()).WithSymbol("cleanup"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return programSpec("pt_ex_acc", ins)
}

func closeSpec(eventsPerf, targets *ebpf.Map) *ebpf.ProgramSpec {
	ins := gatedEventPrefix(targets)
	ins = append(ins, zeroRawEvent(-224)...)
	ins = append(ins, fillCommonEvent(rawKindClose, 0, -224)...)
	ins = append(ins,
		asm.LoadMem(asm.R4, asm.R9, 16, asm.DWord),
		asm.StoreMem(asm.RFP, -200, asm.R4, asm.Word),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -172),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
	)
	ins = append(ins, emitEvent(eventsPerf, -224)...)
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return programSpec("pt_close", ins)
}

func execSpec(eventsPerf, targets *ebpf.Map) *ebpf.ProgramSpec {
	ins := gatedEventPrefix(targets)
	ins = append(ins, zeroRawEvent(-224)...)
	ins = append(ins, fillCommonEvent(rawKindExec, 0, -224)...)
	ins = append(ins,
		asm.LoadMem(asm.R3, asm.R9, 16, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -156),
		asm.Mov.Imm(asm.R2, pathSize),
		asm.FnProbeReadUserStr.Call(),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -172),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
	)
	ins = append(ins, emitEvent(eventsPerf, -224)...)
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return programSpec("pt_exec", ins)
}

func openSpec(eventsPerf, targets *ebpf.Map, name string, pathPtrOffset int16) *ebpf.ProgramSpec {
	ins := gatedEventPrefix(targets)
	ins = append(ins, zeroRawEvent(-224)...)
	ins = append(ins, fillCommonEvent(rawKindOpen, 0, -224)...)
	ins = append(ins,
		asm.LoadMem(asm.R3, asm.R9, pathPtrOffset, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -156),
		asm.Mov.Imm(asm.R2, pathSize),
		asm.FnProbeReadUserStr.Call(),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -172),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
	)
	ins = append(ins, emitEvent(eventsPerf, -224)...)
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return programSpec(name, ins)
}

func cloneExitSpec(eventsPerf, targets *ebpf.Map, name string) *ebpf.ProgramSpec {
	ins := gatedEventPrefix(targets)
	ins = append(ins,
		asm.LoadMem(asm.R8, asm.R9, 16, asm.DWord),
		asm.JSLT.Imm(asm.R8, 0, "exit"),
		asm.JEq.Imm(asm.R8, 0, "exit"),
	)
	ins = append(ins, zeroRawEvent(-224)...)
	ins = append(ins, fillCommonEvent(rawKindClone, 0, -224)...)
	ins = append(ins,
		asm.StoreMem(asm.RFP, -196, asm.R8, asm.Word),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -172),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
	)
	ins = append(ins, emitEvent(eventsPerf, -224)...)
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return programSpec(name, ins)
}

func exitSpec(eventsPerf, targets *ebpf.Map, name string) *ebpf.ProgramSpec {
	ins := gatedEventPrefix(targets)
	ins = append(ins, zeroRawEvent(-224)...)
	ins = append(ins, fillCommonEvent(rawKindExit, 0, -224)...)
	ins = append(ins,
		asm.LoadMem(asm.R4, asm.R9, 16, asm.DWord),
		asm.StoreMem(asm.RFP, -196, asm.R4, asm.Word),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -172),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
	)
	ins = append(ins, emitEvent(eventsPerf, -224)...)
	ins = append(ins,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)
	return programSpec(name, ins)
}
