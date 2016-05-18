package pgsql

import (
	"fmt"
	"github.com/fatih/color"
	"log"
	"sort"
	"strings"
	"sync"
)

type SqlStatus struct {
	query string
	min   int // MicroSecond
	max   int
	list  []int
}

type SqlStatusMap struct {
	smap map[string]*SqlStatus
	emap []*PgsqlMessage // error sql
	mux  sync.RWMutex
}

func (sm *SqlStatusMap) updateErr(msg *PgsqlMessage) (updated bool) {
	if msg.hasError() {
		sm.emap = append(sm.emap, msg)
		return true
	}
	return false
}

func (sm *SqlStatusMap) update(msg *PgsqlMessage) {
	// NOTE: If msg has error, skip smap.
	if len(msg.Query) < 1 {
		return
	}
	if sm.updateErr(msg) {
		return
	}

	sql := msg.Query
	c := int(msg.CostTime.Nanoseconds()) / 1000
	if s, found := sm.smap[sql]; found {
		if c < s.min {
			s.min = c
		}
		if c > s.max {
			s.max = c
		}
		s.list = append(s.list, c)
		return
	}
	s := &SqlStatus{query: sql, min: c, max: c, list: []int{c}}

	sm.mux.Lock()
	sm.smap[sql] = s
	sm.mux.Unlock()
}

type bySqlStatusMax []*SqlStatus

func (s bySqlStatusMax) Len() int           { return len(s) }
func (s bySqlStatusMax) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s bySqlStatusMax) Less(i, j int) bool { return s[i].max > s[j].max }

func (sm *SqlStatusMap) print(n int) {
	if len(sm.smap) < 1 && len(sm.emap) < 1 {
		return
	}

	slist := []*SqlStatus{}
	for _, status := range sm.smap {
		slist = append(slist, status)
	}

	fmt.Println("\n\n")
	sort.Sort(bySqlStatusMax(slist))
	for i := range slist {
		if i > n {
			break
		}

		var showColor int
		min := float64(slist[i].min) / 1000
		max := float64(slist[i].max) / 1000
		// 100ms
		if max > 100 {
			showColor = 1
		}
		if max > 500 {
			showColor = 2
		}

		str := fmt.Sprintf("%s\n", slist[i].query)
		str += fmt.Sprintf("%s: %d\n", "Call-Times", len(slist[i].list))
		str += fmt.Sprintf("%s: %.2f ms\n", "Min-Cost", min)
		str += fmt.Sprintf("%s: %.2f ms\n", "Max-Cost", max)
		dlist := []string{}
		for j := range slist[i].list {
			dlist = append(dlist, fmt.Sprintf("%.2f", float64(slist[i].list[j])/1000))
		}
		str += fmt.Sprintf("%s: %v\n", "Detail-Cost", dlist)

		switch showColor {
		case 1:
			fmt.Printf(color.YellowString(str))
		case 2:
			fmt.Printf(color.RedString(str))
		default:
			fmt.Printf(str)
		}
		fmt.Printf("%s\n\n", strings.Repeat("=", 100))
	}

	if len(sm.emap) > 0 {
		for i := range sm.emap {
			s := color.RedString(fmt.Sprintf("%s, error: %s, errno: %s\n", sm.emap[i].Query, sm.emap[i].ErrorInfo, sm.emap[i].ErrorCode))
			fmt.Printf(s)
			fmt.Printf("%s\n\n", strings.Repeat("=", 100))
		}
	}
}

var sqlMap *SqlStatusMap
var sqlReceiver chan *PgsqlMessage
var statsDone chan bool

func init() {
	sqlMap = &SqlStatusMap{smap: make(map[string]*SqlStatus)}
	sqlReceiver = make(chan *PgsqlMessage, 2000)
	statsDone = make(chan bool)
}

func RunStats(verbose bool) {
	go func() {
		for {
			select {
			case msg := <-sqlReceiver:
				sqlMap.update(msg)
				if verbose {
                    c := float64(msg.CostTime.Nanoseconds()) / 1000 / 1000
                    log.Printf("%s %.2fms", msg.Query, c)
				}
			case _ = <-statsDone:
				return
			}
		}
	}()
}

func PrintStats(n int) {
	sqlMap.print(n)
}

func CloseStats() {
	statsDone <- true
}
