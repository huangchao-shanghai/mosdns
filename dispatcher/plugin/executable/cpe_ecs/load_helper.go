//     Copyright (C) 2020-2021, IrineSistiana
//
//     This file is part of mosdns.
//
//     mosdns is free software: you can redistribute it and/or modify
//     it under the terms of the GNU General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
//
//     mosdns is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU General Public License for more details.
//
//     You should have received a copy of the GNU General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.

package cpe_ecs

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/IrineSistiana/mosdns/v3/dispatcher/pkg/matcher/netlist"
	"github.com/IrineSistiana/mosdns/v3/dispatcher/pkg/utils"
)

// BatchLoad is a helper func to load multiple files using Load.
// It might modify the List and causes List unsorted.
func BatchLoad(l *sync.Map, entries []string) error {
	for _, e := range entries {
		err := Load(l, e)
		if err != nil {
			return fmt.Errorf("failed to load ip entry %s: %w", e, err)
		}
	}
	return nil
}

func BatchLoadFromFiles(l *sync.Map, files []string) error {
	for _, file := range files {
		err := LoadFromFile(l, file)
		if err != nil {
			return fmt.Errorf("failed to load ip file %s: %w", file, err)
		}
	}
	return nil
}

// Load loads data from entry.
// If entry begin with "ext:", Load loads the file by using LoadFromFile.
// Else it loads the entry as a text pattern by using LoadFromText.
func Load(l *sync.Map, entry string) error {
	s1, s2, ok := utils.SplitString2(entry, ":")
	if ok && s1 == "ext" {
		return LoadFromFile(l, s2)
	}
	return LoadFromText(l, entry)
}

// LoadFromReader loads IP list from a reader.
// It might modify the List and causes List unsorted.
func LoadFromReader(l *sync.Map, reader io.Reader, tag string) error {
	scanner := bufio.NewScanner(reader)

	// count how many lines we have read.
	lineCounter := 0
	for scanner.Scan() {
		lineCounter++
		s := scanner.Text()
		s = strings.TrimSpace(s)
		//仅当 tag 匹配时导入
		if len(tag) > 0 && strings.TrimSpace(s[:len(tag)]) != tag {
			continue
		}
		s = utils.RemoveComment(s, "#")
		s = utils.RemoveComment(s, " ")
		if len(s) == 0 {
			continue
		}
		err := LoadFromText(l, s)
		if err != nil {
			return fmt.Errorf("invalid data at line #%d: %w", lineCounter, err)
		}
	}
	return scanner.Err()
}

// LoadFromText loads an IP from tag cpeip ecsip.
// It might modify the List and causes List unsorted.
func LoadFromText(l *sync.Map, s string) error {
	words := strings.Fields(s)
	cpeip, _, err := netlist.ParseIP(words[1])
	if err != nil {
		return fmt.Errorf("invaild cpe ip address %s", s)
	}
	ecsip, v6, err := netlist.ParseIP(words[2])
	if err != nil {
		return fmt.Errorf("invaild ecs ip address %s", s)
	}
	l.Store(cpeip, &cpe_ecs_ip{
		cpeip:      cpeip,
		ecsip:      ecsip,
		storedTime: time.Now(),
		v6:         v6 != 0,
	})
	return nil
}

// LoadFromFile loads ip from a text file or a geoip file.
// If file contains a ':' and has format like 'geoip:cn', it will be read as a geoip file.
// It might modify the List and causes List unsorted.
func LoadFromFile(l *sync.Map, file string) error {
	if strings.Contains(file, ":") {
		tmp := strings.SplitN(file, ":", 2)
		return LoadFromTextFile(l, tmp[0], tmp[1]) // file and tag
	} else {
		return LoadFromTextFile(l, file, "")
	}
}

// LoadFromTextFile reads IP list from a text file.
// It might modify the List and causes List unsorted.
func LoadFromTextFile(l *sync.Map, file string, tag string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	return LoadFromReader(l, bytes.NewReader(b), tag)
}
