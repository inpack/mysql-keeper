// Copyright 2017 Eryx <evorui at gmail dot com>, All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hlog4g/hlog"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
	"github.com/sysinner/incore/inconf"
	"github.com/sysinner/incore/inutils/filerender"
	"github.com/ziutek/mymysql/mysql"
	_ "github.com/ziutek/mymysql/native"
)

var (
	mysql_prefix          = "/home/action/apps/mysql57"
	mysql_datadir         = mysql_prefix + "/data"
	mysql_bin_mysql       = mysql_prefix + "/bin/mysql57"
	mysql_bin_mysqld      = mysql_prefix + "/bin/mysql57d"
	mysql_bin_mysqladmin  = mysql_prefix + "/bin/mysql57admin"
	mysql_pidfile         = mysql_prefix + "/run/mysql.pid"
	mysql_sock            = mysql_prefix + "/run/mysql.sock"
	mysql_sock_lock       = mysql_prefix + "/run/mysql.sock.lock"
	mysql_conf_init       = mysql_prefix + "/etc/init_option.json"
	mysql_conf_main       = mysql_prefix + "/etc/my.cnf"
	mysql_conf_main_tpl   = mysql_prefix + "/etc/my.cnf.default"
	mysql_conf_server     = mysql_prefix + "/etc/my.cnf.d/server.cnf"
	mysql_conf_server_tpl = mysql_prefix + "/etc/my.server.cnf.default"
	mysql_mem_min         = int32(16) // in MiB
	mu                    sync.Mutex
	cfg_mu                sync.Mutex
	cfg_last              EnvConfig
	cfg_next              EnvConfig
	myPodCfr              *inconf.PodConfigurator
)

type EnvConfig struct {
	Inited   bool              `json:"inited"`
	RootAuth string            `json:"root_auth"`
	Resource EnvConfigResource `json:"resource"`
	Database EnvConfigDatabase `json:"database"`
	Users    []EnvConfigUser   `json:"users"`
	Updated  time.Time         `json:"updated"`
}

type EnvConfigResource struct {
	Ram int32 `json:"ram"`
	Cpu int32 `json:"cpu"`
}

type EnvConfigDatabase struct {
	Name  string       `json:"name"`
	Items types.Labels `json:"items"`
}

type EnvConfigUser struct {
	Name string `json:"name"`
	Auth string `json:"auth"`
}

func (cfg *EnvConfig) UserSync(item EnvConfigUser) {

	cfg_mu.Lock()
	defer cfg_mu.Unlock()

	for i, v := range cfg.Users {

		if v.Name == item.Name {
			cfg.Users[i] = item
			return
		}
	}

	cfg.Users = append(cfg.Users, item)
}

func (cfg *EnvConfig) UserGet(name string) *EnvConfigUser {

	cfg_mu.Lock()
	defer cfg_mu.Unlock()

	for _, v := range cfg.Users {

		if v.Name == name {
			return &v
		}
	}

	return nil
}

func main() {

	for {
		time.Sleep(3e9)
		do()
	}
}

func do() {

	fpbin, err := os.Open(mysql_bin_mysqld)
	if err != nil {
		hlog.Print("error", err.Error())
		return
	}
	fpbin.Close()

	var (
		tstart = time.Now()
		podCfr *inconf.PodConfigurator
		appCfg *inconf.AppConfigGroup
	)
	cfg_next = EnvConfig{}

	//
	{
		if myPodCfr != nil {
			podCfr = myPodCfr

			if !podCfr.Update() {
				return
			}

		} else {

			if podCfr, err = inconf.NewPodConfigurator(); err != nil {
				hlog.Print("error", err.Error())
				return
			}
		}

		appCfr := podCfr.AppConfigurator("sysinner-mysql-*")
		if appCfr == nil {
			hlog.Print("error", "No AppSpec (sysinner-mysql) Found")
			return
		}
		if appCfg = appCfr.AppConfigQuery("cfg/sysinner-mysql"); appCfg == nil {
			hlog.Print("error", "No App Config (sysinner-mysql) Found")
			return
		}

		if podCfr.PodSpec().Box.Resources.MemLimit > 0 {
			cfg_next.Resource.Ram = podCfr.PodSpec().Box.Resources.MemLimit
		}
		if podCfr.PodSpec().Box.Resources.CpuLimit > 0 {
			cfg_next.Resource.Cpu = podCfr.PodSpec().Box.Resources.CpuLimit
		}
	}

	if v, ok := appCfg.ValueOK("db_name"); ok {
		cfg_next.Database = EnvConfigDatabase{
			Name: v.String(),
		}
	} else {
		hlog.Print("error", "No db_name Found")
		return
	}

	if v, ok := appCfg.ValueOK("db_user"); ok {

		vp, ok := appCfg.ValueOK("db_auth")
		if !ok {
			hlog.Print("error", "No db_auth Found")
			return
		}

		cfg_next.UserSync(EnvConfigUser{
			Name: v.String(),
			Auth: vp.String(),
		})

	} else {
		hlog.Print("error", "No db_user Found")
		return
	}

	if v, ok := appCfg.ValueOK("memory_usage_limit"); ok {

		ram_pc := v.Int32()

		if ram_pc < 10 {
			ram_pc = 10
		} else if ram_pc > 100 {
			ram_pc = 100
		}

		ram_pc = (cfg_next.Resource.Ram * ram_pc) / 100
		if offset := ram_pc % mysql_mem_min; offset > 0 {
			ram_pc -= offset
		}
		if ram_pc < mysql_mem_min {
			ram_pc = mysql_mem_min
		}
		cfg_next.Resource.Ram = ram_pc

	} else {
		hlog.Print("error", "No memory_usage_limit Found")
		return
	}

	//
	if cfg_next.Resource.Ram < mysql_mem_min {
		hlog.Print("error", "Not enough Memory to fit this MySQL Instance")
		return
	}

	//
	if cfg_last.Database.Name == "" {
		json.DecodeFile(mysql_conf_init, &cfg_last)
	}

	//
	if err := init_cnf(); err != nil {
		hlog.Print("error", err.Error())
		return
	}

	// s1
	if err := init_datadir(); err != nil {
		hlog.Print("error", err.Error())
		return
	}

	if cfg_last.Resource.Ram != cfg_next.Resource.Ram {
		if err := restart(); err != nil {
			hlog.Print("error", err.Error())
			return
		}
		cfg_last.Resource.Ram = cfg_next.Resource.Ram
		cfg_last.Resource.Cpu = cfg_next.Resource.Cpu

	} else {

		if err := start(); err != nil {
			hlog.Print("error", err.Error())
			return
		}
	}

	// s2
	if err := init_root_auth(); err != nil {
		hlog.Printf("error", "init_root_auth %s", err.Error())
		return
	}

	// s3
	if err := init_db(); err != nil {
		hlog.Printf("error", "init_db %s", err.Error())
		return
	}

	if err := init_user(); err != nil {
		hlog.Printf("error", "init_user %s", err.Error())
		return
	}

	hlog.Printf("info", "setup in %v", time.Since(tstart))

	myPodCfr = podCfr
}

func init_cnf() error {

	if cfg_last.Inited && cfg_last.Resource.Ram == cfg_next.Resource.Ram {
		return nil
	}

	//
	ram := int(cfg_next.Resource.Ram)
	sets := map[string]interface{}{
		"project_prefix":                 mysql_prefix,
		"env_ram_size":                   fmt.Sprintf("%dM", ram),
		"server_key_buffer_size":         fmt.Sprintf("%dM", ram/4),
		"server_query_cache_size":        fmt.Sprintf("%dM", ram/8),
		"server_innodb_buffer_pool_size": fmt.Sprintf("%dM", ram/4),
	}

	if !cfg_last.Inited || cfg_last.Resource.Ram != cfg_next.Resource.Ram {

		if err := filerender.Render(mysql_conf_server_tpl, mysql_conf_server, 0644, sets); err != nil {
			return err
		}
	}

	if !cfg_last.Inited {

		if err := filerender.Render(mysql_conf_main_tpl, mysql_conf_main, 0644, sets); err != nil {
			return err
		}

		cfg_last.Resource.Ram = cfg_next.Resource.Ram
		cfg_last.Resource.Cpu = cfg_next.Resource.Cpu
	}

	return nil
}

func init_datadir() error {

	mu.Lock()
	defer mu.Unlock()

	if cfg_last.Inited {
		return nil
	}

	if cfg_last.RootAuth != "" {
		return errors.New("Root Password Already Setup")
	}

	// writeable test!
	cfg_last.Updated = time.Now()
	if err := json.EncodeToFile(cfg_last, mysql_conf_init, "  "); err != nil {
		return err
	}

	_, err := os.Open(mysql_datadir + "/auto.cnf")
	if err != nil && os.IsNotExist(err) {
		_, err = exec.Command(mysql_bin_mysqld, "--initialize-insecure").Output()
		if err != nil {
			hlog.Printf("error", "initialize-insecure server %s", err.Error())
		} else {
			hlog.Printf("info", "initialize-insecure server ok")
		}
	}

	if err == nil {
		cfg_last.Inited = true
		err = json.EncodeToFile(cfg_last, mysql_conf_init, "  ")
	}

	return err
}

func clean_runlock() {
	os.Remove(mysql_sock)
	os.Remove(mysql_pidfile)
}

func start() error {

	mu.Lock()
	defer mu.Unlock()

	hlog.Printf("info", "start()")

	if !cfg_last.Inited {
		return errors.New("No Init")
	}

	if pidof() > 0 {
		return nil
	}

	clean_runlock()

	os.Remove(mysql_pidfile)
	os.Remove(mysql_sock)
	os.Remove(mysql_sock_lock)
	// _, err := exec.Command(mysql_bin_mysqld, ">", "/dev/null", "2>&1", "&").Output()
	_, err := exec.Command("/bin/sh", "-c", mysql_bin_mysqld+" > /dev/null 2>&1 &").Output()

	time.Sleep(1e9)

	if err != nil {
		hlog.Printf("error", "start mysqld %s", err.Error())
	} else {
		hlog.Printf("info", "start mysqld ok")
	}

	return err
}

func restart() error {

	mu.Lock()
	defer mu.Unlock()

	if !cfg_last.Inited {
		return errors.New("No Init")
	}

	var err error

	if pid := pidof(); pid > 0 {
		hlog.Printf("info", "kill HUP %d", pid)
		_, err = exec.Command("kill", "-s", "HUP", strconv.Itoa(pid)).Output()
		if err != nil {
			hlog.Printf("error", "kill HUP %s", err.Error())
		} else {
			hlog.Printf("info", "kill HUP ok")
		}

	} else {
		// _, err = exec.Command(mysql_bin_mysqld, ">", "/dev/null", "2>&1", "&").Output()
		_, err := exec.Command("/bin/sh", "-c", mysql_bin_mysqld+" > /dev/null 2>&1 &").Output()
		time.Sleep(1e9)
		if err != nil {
			hlog.Printf("error", "start mysqld %s", err.Error())
		} else {
			hlog.Printf("info", "start mysqld ok")
		}
	}

	return err
}

func pidof() int {

	//
	for i := 0; i < 3; i++ {

		pidout, err := exec.Command("pgrep", "-f", mysql_bin_mysqld).Output()
		pid, _ := strconv.Atoi(strings.TrimSpace(string(pidout)))

		if err != nil || pid == 0 {
			time.Sleep(3e9)
			continue
		}

		return pid
	}

	return 0
}

func init_root_auth() error {

	mu.Lock()
	defer mu.Unlock()

	hlog.Printf("info", "init_root_auth()")

	if !cfg_last.Inited {
		return errors.New("No Init")
	}

	if cfg_last.RootAuth != "" {
		return nil
	}

	root_auth := idhash.RandHexString(32)

	_, err := exec.Command(mysql_bin_mysqladmin,
		"-u", "root",
		"password", root_auth,
		"--socket="+mysql_sock,
	).Output()

	if err != nil {
		hlog.Printf("error", "init root pass err %s", err.Error())
		if pid := pidof(); pid > 0 {
			hlog.Printf("info", "kill %d", pid)
			exec.Command("kill", "-9", strconv.Itoa(pid)).Output()
			clean_runlock()
			time.Sleep(1e9)
		}

		// --skip-grant-tables --skip-networking
		_, err = exec.Command("/bin/sh", "-c", mysql_bin_mysqld+" --skip-grant-tables > /dev/null 2>&1 &").Output()
		time.Sleep(3e9)
		if err == nil {

			sql := strings.Join([]string{
				`FLUSH PRIVILEGES;`,
				fmt.Sprintf(`CREATE USER IF NOT EXISTS 'root'@'localhost' IDENTIFIED BY "%s";`, root_auth),
				fmt.Sprintf(`SET PASSWORD FOR 'root'@'localhost' = PASSWORD("%s");`, root_auth),
				`GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION;`,
				`FLUSH PRIVILEGES;`,
			}, " ")
			hlog.Printf("info", "init root user")

			if err = conn_exec(sql); err != nil {
				hlog.Printf("error", "init root pass err %s", err.Error())
			}
		} else {
			hlog.Printf("error", "init root pass err, start skip-grant-tables error %s", err.Error())
		}

		if pid := pidof(); pid > 0 {
			hlog.Printf("info", "init root pass err, kill and start %d", pid)
			exec.Command("kill", "-9", strconv.Itoa(pid)).Output()
			clean_runlock()
			time.Sleep(3e9)
		}

		if err == nil {
			hlog.Printf("info", "start ...")
			if _, e := exec.Command("/bin/sh", "-c", mysql_bin_mysqld+" > /dev/null 2>&1 &").Output(); e != nil {
				return e
			}
			hlog.Printf("info", "start ... ok")
			time.Sleep(1e9)
		}
	}

	if err == nil {
		hlog.Printf("info", "init root password ok")
		cfg_last.RootAuth = root_auth
		err = json.EncodeToFile(cfg_last, mysql_conf_init, "  ")
	}

	return err
}

func init_db() error {

	mu.Lock()
	defer mu.Unlock()

	if !cfg_last.Inited {
		return errors.New("No Init")
	}

	var err error

	if cfg_next.Database.Name != "" &&
		cfg_last.Database.Name == "" {

		if err = conn_exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", cfg_next.Database.Name)); err != nil {
			return err
		}

		hlog.Printf("info", "create database %s ok", cfg_next.Database.Name)

		cfg_last.Database = cfg_next.Database
		err = json.EncodeToFile(cfg_last, mysql_conf_init, "  ")
	}

	return err
}

func init_user() error {

	if !cfg_last.Inited {
		return errors.New("No Init")
	}

	if cfg_last.Database.Name == "" {
		return errors.New("No Database Found")
	}

	var err error

	for _, v := range cfg_next.Users {

		if prev := cfg_last.UserGet(v.Name); prev == nil {

			conn_exec(fmt.Sprintf(`DROP USER "%s"@"%%"`, v.Name))

			if err = conn_exec(fmt.Sprintf(
				`CREATE USER "%s"@"%%" IDENTIFIED BY "%s"`,
				v.Name, v.Auth,
			)); err != nil {
				return err
			}

			if err = conn_exec(fmt.Sprintf(
				`GRANT ALL PRIVILEGES ON %s.* TO "%s"@"%%" WITH GRANT OPTION`,
				cfg_last.Database.Name, v.Name,
			)); err != nil {
				return err
			}

			if err = conn_exec("FLUSH PRIVILEGES"); err != nil {
				return err
			}

			hlog.Printf("info", "create user %s", v.Name)

			cfg_last.UserSync(v)
			err = json.EncodeToFile(cfg_last, mysql_conf_init, "  ")
		}
	}

	return err
}

func conn_exec(sql string) error {

	db := mysql.New("unix", "", mysql_sock, "root", cfg_last.RootAuth)

	err := db.Connect()
	if err != nil {
		hlog.Printf("info", "conn err %s", err.Error())
		return err
	}

	defer db.Close()

	_, _, err = db.Query(sql)

	return err
}
