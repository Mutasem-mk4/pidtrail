//go:build linux

package procfs

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type SocketInfo struct {
	Network string
	Local   string
	Remote  string
}

func FindPIDsByComm(name string) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]int, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		commBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(commBytes)) == name {
			out = append(out, pid)
		}
	}
	return out, nil
}

func ResolveSocket(pid, fd int) (SocketInfo, error) {
	linkPath := filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(fd))
	target, err := os.Readlink(linkPath)
	if err != nil {
		return SocketInfo{}, err
	}
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return SocketInfo{}, fmt.Errorf("fd %d is not a socket", fd)
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	for _, item := range []struct {
		network string
		path    string
		ipv6    bool
	}{
		{network: "tcp", path: filepath.Join("/proc", strconv.Itoa(pid), "net", "tcp")},
		{network: "tcp6", path: filepath.Join("/proc", strconv.Itoa(pid), "net", "tcp6"), ipv6: true},
	} {
		info, err := findInode(item.path, inode, item.network, item.ipv6)
		if err == nil {
			return info, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			continue
		}
	}
	return SocketInfo{}, fmt.Errorf("socket inode %s not found", inode)
}

func findInode(path, inode, network string, ipv6 bool) (SocketInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return SocketInfo{}, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[9] != inode {
			continue
		}
		local, err := parseAddrPort(fields[1], ipv6)
		if err != nil {
			return SocketInfo{}, err
		}
		remote, err := parseAddrPort(fields[2], ipv6)
		if err != nil {
			return SocketInfo{}, err
		}
		return SocketInfo{
			Network: network,
			Local:   local,
			Remote:  remote,
		}, nil
	}
	if err := scanner.Err(); err != nil {
		return SocketInfo{}, err
	}
	return SocketInfo{}, os.ErrNotExist
}

func parseAddrPort(value string, ipv6 bool) (string, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid address field %q", value)
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", err
	}
	addr, err := parseHexAddr(parts[0], ipv6)
	if err != nil {
		return "", err
	}
	return netip.AddrPortFrom(addr, uint16(port)).String(), nil
}

func parseHexAddr(value string, ipv6 bool) (netip.Addr, error) {
	raw, err := hex.DecodeString(value)
	if err != nil {
		return netip.Addr{}, err
	}
	if ipv6 {
		if len(raw) != 16 {
			return netip.Addr{}, fmt.Errorf("unexpected ipv6 length")
		}
		out := make([]byte, 16)
		for i := 0; i < 16; i += 4 {
			out[i+0] = raw[i+3]
			out[i+1] = raw[i+2]
			out[i+2] = raw[i+1]
			out[i+3] = raw[i+0]
		}
		addr, ok := netip.AddrFromSlice(out)
		if !ok {
			return netip.Addr{}, fmt.Errorf("invalid ipv6 address")
		}
		return addr, nil
	}
	if len(raw) != 4 {
		return netip.Addr{}, fmt.Errorf("unexpected ipv4 length")
	}
	return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), nil
}
