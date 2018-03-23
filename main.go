package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"sort"
	"strings"
	"sync"

	"github.com/tidwall/finn"
	"github.com/tidwall/match"
	"github.com/tidwall/redcon"
	"strconv"
)

func main() {
	var port int
	var backend string
	var durability string
	var consistency string
	var loglevel string
	var join string
	var dir string

	flag.IntVar(&port, "p", 7481, "Bind port")
	flag.StringVar(&backend, "backend", "fastlog", "Raft log backend [fastlog,bolt,inmem]")
	flag.StringVar(&durability, "durability", "medium", "Log durability [low,medium,high]")
	flag.StringVar(&consistency, "consistency", "medium", "Raft consistency [low,medium,high]")
	flag.StringVar(&loglevel, "loglevel", "notice", "Log level [quiet,warning,notice,verbose,debug]")
	flag.StringVar(&dir, "dir", "data", "Data directory")
	flag.StringVar(&join, "join", "", "Join a cluster by providing an address")
	flag.Parse()

	var opts finn.Options

	switch strings.ToLower(backend) {
	default:
		log.Fatalf("invalid backend '%v'", backend)
	case "fastlog":
		opts.Backend = finn.FastLog
	case "bolt":
		opts.Backend = finn.Bolt
	case "inmem":
		opts.Backend = finn.InMem
	}
	switch strings.ToLower(durability) {
	default:
		log.Fatalf("invalid durability '%v'", durability)
	case "low":
		opts.Durability = finn.Low
	case "medium":
		opts.Durability = finn.Medium
	case "high":
		opts.Durability = finn.High
	}
	switch strings.ToLower(consistency) {
	default:
		log.Fatalf("invalid consistency '%v'", consistency)
	case "low":
		opts.Consistency = finn.Low
	case "medium":
		opts.Consistency = finn.Medium
	case "high":
		opts.Consistency = finn.High
	}
	switch strings.ToLower(loglevel) {
	default:
		log.Fatalf("invalid loglevel '%v'", loglevel)
	case "quiet":
		opts.LogOutput = ioutil.Discard
	case "warning":
		opts.LogLevel = finn.Warning
	case "notice":
		opts.LogLevel = finn.Notice
	case "verbose":
		opts.LogLevel = finn.Verbose
	case "debug":
		opts.LogLevel = finn.Debug
	}
	n, err := finn.Open(dir, fmt.Sprintf(":%d", port), join, NewClone(), &opts)
	if err != nil {
		if opts.LogOutput == ioutil.Discard {
			log.Fatal(err)
		}
	}
	defer n.Close()
	select {}
}

// Clone represent a Redis clone machine
type Clone struct {
	mu             sync.RWMutex
	keys           map[string]int64
	transactionIds map[string]bool
}

// NewClone create a new clone
func NewClone() *Clone {
	val := &Clone{
		keys:           make(map[string]int64),
		transactionIds: make(map[string]bool),
	}
	val.keys["2V4NoRKExqotxJc4oX9AU4xRniJTidYSYYYmrvXuhgajvpo5XToo9rTY1wpWcUWpuhenXdo2DHnuhMCnfNddsqsi"] = 1000000000000000
	return val
}

// Command processes a command
func (kvm *Clone) Command(m finn.Applier, conn redcon.Conn, cmd redcon.Command) (interface{}, error) {
	switch strings.ToLower(string(cmd.Args[0])) {
	default:
		return nil, finn.ErrUnknownCommand
		/*
	case "set":
		if len(cmd.Args) != 3 {
			return nil, finn.ErrWrongNumberOfArguments
		}
		return m.Apply(conn, cmd,
			func() (interface{}, error) {
				kvm.mu.Lock()
				kvm.keys[string(cmd.Args[1])] = cmd.Args[2]
				kvm.mu.Unlock()
				return nil, nil
			},
			func(v interface{}) (interface{}, error) {
				conn.WriteString("OK")
				return nil, nil
			},
		)
		*/
	case "pay":
		if len(cmd.Args) != 6 {
			return nil, finn.ErrWrongNumberOfArguments
		}
		return m.Apply(conn, cmd,
			func() (interface{}, error) {

				from := string(cmd.Args[1])
				to := string(cmd.Args[2])

				//toVal := kvm.keys[to]
				amount := string(cmd.Args[3])
				ri := string(cmd.Args[4])
				sign := string(cmd.Args[5])

				result := verifyTransaction(from,to,amount,ri,sign)
				if result == false {
					return nil, finn.ErrSignature
				}
				amountInt, err := strconv.ParseInt(amount,10,64)
				if err != nil {
					return nil, finn.ErrInvalidArguments
				}
				if amountInt <= 0 {
					return nil, finn.ErrAccountError
				}

				kvm.mu.Lock()
				fromVal := kvm.keys[from]
				if fromVal < amountInt {
					kvm.mu.Unlock()
					return nil, finn.ErrAccountError
				}
				if kvm.transactionIds[ri] == true {
					kvm.mu.Unlock()
					return nil, finn.ErrRepeatedTransactionId
				}
				kvm.transactionIds[ri] = true

				kvm.keys[from] = kvm.keys[from] - amountInt
				kvm.keys[to] = kvm.keys[to] + amountInt
				kvm.mu.Unlock()
				return nil, nil
			},
			func(v interface{}) (interface{}, error) {
				conn.WriteString("OK")
				return nil, nil
			},
		)

	case "get":
		if len(cmd.Args) != 2 {
			return nil, finn.ErrWrongNumberOfArguments
		}
		return m.Apply(conn, cmd, nil,
			func(interface{}) (interface{}, error) {
				kvm.mu.RLock()
				val, ok := kvm.keys[string(cmd.Args[1])]
				kvm.mu.RUnlock()
				if !ok {
					conn.WriteNull()
				} else {
					conn.WriteBulk([]byte(strconv.FormatInt(val,10)))
				}
				return nil, nil
			},
		)
/*	case "del":
		if len(cmd.Args) < 2 {
			return nil, finn.ErrWrongNumberOfArguments
		}
		return m.Apply(conn, cmd,
			func() (interface{}, error) {
				var n int
				kvm.mu.Lock()
				for i := 1; i < len(cmd.Args); i++ {
					key := string(cmd.Args[i])
					if _, ok := kvm.keys[key]; ok {
						delete(kvm.keys, key)
						n++
					}
				}
				kvm.mu.Unlock()
				return n, nil
			},
			func(v interface{}) (interface{}, error) {
				n := v.(int)
				conn.WriteInt(n)
				return nil, nil
			},
		)*/
	case "keys":
		if len(cmd.Args) != 2 {
			return nil, finn.ErrWrongNumberOfArguments
		}
		pattern := string(cmd.Args[1])
		return m.Apply(conn, cmd, nil,
			func(v interface{}) (interface{}, error) {
				var keys []string
				kvm.mu.RLock()
				for key := range kvm.keys {
					if match.Match(key, pattern) {
						keys = append(keys, key)
					}
				}
				kvm.mu.RUnlock()
				sort.Strings(keys)
				conn.WriteArray(len(keys))
				for _, key := range keys {
					conn.WriteBulkString(key)
				}
				return nil, nil
			},
		)
	}
}

type HashData struct {
	keys           map[string]int64
	transactionIds map[string]bool
}

// Restore restores a snapshot
func (kvm *Clone) Restore(rd io.Reader) error {
	kvm.mu.Lock()
	defer kvm.mu.Unlock()
	data, err := ioutil.ReadAll(rd)
	if err != nil {
		return err
	}

	var hdata HashData

	if err := json.Unmarshal(data, &hdata); err != nil {
		return err
	}

	kvm.keys = hdata.keys
	kvm.transactionIds = hdata.transactionIds
	return nil
}

// Snapshot creates a snapshot
func (kvm *Clone) Snapshot(wr io.Writer) error {
	kvm.mu.RLock()
	defer kvm.mu.RUnlock()
	var hdata HashData
	hdata.keys = kvm.keys
	hdata.transactionIds = kvm.transactionIds
	data, err := json.Marshal(hdata)
	if err != nil {
		return err
	}
	if _, err := wr.Write(data); err != nil {
		return err
	}
	return nil
}
