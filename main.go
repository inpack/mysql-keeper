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
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hooto/hflag4g/hflag"
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
	mysql_sv              = "57"
	mysql_prefix          = "/opt/mysql/mysql57"
	mysql_datadir         = mysql_prefix + "/data"
	mysql_bin_mysql       = mysql_prefix + "/bin/mysql57"
	mysql_bin_mysqld      = mysql_prefix + "/bin/mysql57d"
	mysql_bin_mysqladmin  = mysql_prefix + "/bin/mysql57admin"
	mysql_pidfile         = mysql_prefix + "/run/mysql.pid"
	mysql_sock            = mysql_prefix + "/run/mysql.sock"
	mysql_sock_lock       = mysql_prefix + "/run/mysql.sock.lock"
	mysql_cnf_init        = mysql_prefix + "/etc/init_option.json"
	mysql_cnf_main        = mysql_prefix + "/etc/my.cnf"
	mysql_cnf_main_tpl    = mysql_keeper_prefix + "/misc/etc/my.cnf.default"
	mysql_cnf_server      = mysql_prefix + "/etc/my.cnf.d/server.cnf"
	mysql_cnf_server_tpl  = mysql_keeper_prefix + "/misc/etc/my.server.cnf.default"
	mysql_ssl_bin         = mysql_prefix + "/bin/mysql_ssl_rsa_setup"
	mysql_ssl_server_cert = mysql_datadir + "/server-cert.pem"
	mysql_gr_server       = mysql_prefix + "/etc/my.cnf.d/server.gr.cnf"
	mysql_gr_server_tpl   = mysql_keeper_prefix + "/misc/5.7/server.gr.cnf.default"
	mysql_mem_min         = int32(16) // in MiB
	mysql_keeper_prefix   = "/opt/mysql/keeper"
	mu                    sync.Mutex
	cfg_mu                sync.Mutex
	cfg_last              EnvConfig
	cfg_next              EnvConfig
	myPodCfr              *inconf.PodConfigurator
)

type EnvConfig struct {
	Inited    bool                   `json:"inited"`
	RootAuth  string                 `json:"root_auth"`
	Resource  EnvConfigResource      `json:"resource"`
	Database  EnvConfigDatabase      `json:"database"`
	Users     []EnvConfigUser        `json:"users"`
	Updated   time.Time              `json:"updated"`
	Gr        ConfigGroupReplication `json:"gr"`
	GrInited  bool                   `json:"-"`
	GrStarted bool                   `json:"-"`
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

type ConfigGroupReplication struct {
	Enable       bool   `json:"enable"`
	MultiPrimary bool   `json:"multi_primary"`
	ServerId     int    `json:"server_id"`
	Port         int    `json:"port"`
	GroupName    string `json:"group_name"`
	GroupSeeds   string `json:"group_seeds"`
	BindAddress  string `json:"bind_address"`
	ReportHost   string `json:"report_host"`
	IpWhitelist  string `json:"ip_whitelist"`
	LocalAddress string `json:"local_address"`
	Auth         string `json:"auth"`
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

	if v, ok := hflag.ValueOK("sv"); ok {
		switch v.String() {
		case "56", "57":
			mysql_sv = v.String()

			mysql_prefix = "/opt/mysql/mysql" + mysql_sv
			mysql_bin_mysql = mysql_prefix + "/bin/mysql" + mysql_sv
			mysql_bin_mysqld = mysql_prefix + "/bin/mysql" + mysql_sv + "d"
			mysql_bin_mysqladmin = mysql_prefix + "/bin/mysql" + mysql_sv + "admin"
		}
	}

	for {
		time.Sleep(3e9)
		do()
	}
}

func do() {

	if !fileExist(mysql_bin_mysqld) {
		hlog.Print("error", mysql_bin_mysqld+" not found")
		return
	}

	var (
		tstart = time.Now()
		podCfr *inconf.PodConfigurator
		appCfr *inconf.AppConfigurator
		appCfg *inconf.AppConfigGroup
		err    error
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

			myPodCfr = podCfr
		}

		appCfr = podCfr.AppConfigurator("sysinner-mysql-*")
		if appCfr != nil {
			appCfg = appCfr.AppConfigQuery("cfg/sysinner-mysql")
		}

		if appCfg == nil {
			appCfg = podCfr.AppConfigQuery("cfg/sysinner-mysql")
		}

		if appCfg == nil {
			hlog.Print("error", "No AppSpec (sysinner-mysql-*) or AppOption (cfg/sysinner-mysql) Found")
			return
		}
	}

	//
	if cfg_last.Database.Name == "" {
		json.DecodeFile(mysql_cnf_init, &cfg_last)
	}

	//
	if err := setupConf(podCfr, appCfg); err != nil {
		hlog.Print("error", err.Error())
		return
	}

	if err := setupGrConf(podCfr); err != nil {
		hlog.Printf("error", "setup gr err %s", err.Error())
		return
	}

	// s1
	if err := init_datadir(); err != nil {
		hlog.Print("error", err.Error())
		return
	}

	if err := setupSsl(); err != nil {
		hlog.Print("error", err.Error())
		return
	}

	if !reflect.DeepEqual(cfg_last.Resource, cfg_next.Resource) ||
		!reflect.DeepEqual(cfg_last.Gr, cfg_next.Gr) {

		if err := restart(); err != nil {
			hlog.Print("error", err.Error())
			return
		}

		hlog.Printf("info", "refresh configs")

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

	if err := setupGrOpr(podCfr); err != nil {
		hlog.Printf("error", "setup gr err %s", err.Error())
		return
	}

	cfg_last.Resource = cfg_next.Resource
	cfg_last.Gr = cfg_next.Gr
	confFlush()

	hlog.Printf("debug", "setup in %v", time.Since(tstart))

	myPodCfr = podCfr
}

func setupConf(podCfr *inconf.PodConfigurator, appCfg *inconf.AppConfigGroup) error {

	if podCfr.PodSpec().Box.Resources.MemLimit > 0 {
		cfg_next.Resource.Ram = podCfr.PodSpec().Box.Resources.MemLimit
	}
	if podCfr.PodSpec().Box.Resources.CpuLimit > 0 {
		cfg_next.Resource.Cpu = podCfr.PodSpec().Box.Resources.CpuLimit
	}

	if v, ok := appCfg.ValueOK("db_name"); ok {
		cfg_next.Database = EnvConfigDatabase{
			Name: v.String(),
		}
	} else {
		return errors.New("No db_name Found")
	}

	if v, ok := appCfg.ValueOK("db_user"); ok {

		vp, ok := appCfg.ValueOK("db_auth")
		if !ok {
			return errors.New("No db_auth Found")
		}

		cfg_next.UserSync(EnvConfigUser{
			Name: v.String(),
			Auth: vp.String(),
		})

	} else {
		return errors.New("No db_user Found")
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
		return errors.New("No memory_usage_limit Found")
	}

	//
	if cfg_next.Resource.Ram < mysql_mem_min {
		return errors.New("Not enough Memory to fit this MySQL Instance")
	}

	if cfg_last.Inited && reflect.DeepEqual(cfg_last.Resource, cfg_next.Resource) {
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

	if !cfg_last.Inited || !reflect.DeepEqual(cfg_last.Resource, cfg_next.Resource) {

		if err := filerender.Render(mysql_cnf_server_tpl, mysql_cnf_server, 0644, sets); err != nil {
			return err
		}
	}

	if !cfg_last.Inited {

		if err := filerender.Render(mysql_cnf_main_tpl, mysql_cnf_main, 0644, sets); err != nil {
			return err
		}
	}

	return nil
}

func fileExist(v string) bool {
	_, err := os.Stat(v)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
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

	var err error

	// writeable test!
	cfg_last.Updated = time.Now()
	if err := confFlush(); err != nil {
		return err
	}

	if !fileExist(mysql_datadir + "/auto.cnf") {
		_, err = exec.Command(mysql_bin_mysqld, "--initialize-insecure").Output()
		if err != nil {
			hlog.Printf("error", "initialize-insecure server %s", err.Error())
		} else {
			hlog.Printf("info", "initialize-insecure server ok")
		}
	}

	if err == nil {
		cfg_last.Inited = true
		err = confFlush()
	}

	return err
}

func setupSsl() error {

	mu.Lock()
	defer mu.Unlock()

	if !fileExist(mysql_ssl_bin) {
		return nil
	}

	if !fileExist(mysql_ssl_server_cert) {

		if _, err := exec.Command(mysql_ssl_bin, []string{
			"--datadir=" + mysql_datadir,
		}...).Output(); err != nil {
			return err
		}
	}

	return nil
}

func setupGrConf(pod *inconf.PodConfigurator) error {

	if pod.Pod.Operate.ReplicaCap < 2 ||
		len(pod.Pod.Operate.Replicas) < int(pod.Pod.Operate.ReplicaCap) {
		return nil
	}

	app := pod.AppConfigurator("sysinner-mysql-gr")
	if app == nil {
		return nil // errors.New("No App Config (sysinner-mysql-*) Found")
	}

	if app.AppSpec().Meta.ID != "sysinner-mysql-gr" {
		return nil
	}

	appCfg := app.AppConfigQuery("cfg/sysinner-mysql")
	if appCfg == nil {
		return errors.New("No App Config (sysinner-mysql-*) Found")
	}

	if v, ok := appCfg.ValueOK("gr_auth"); ok {
		cfg_next.Gr.Auth = v.String()
	}
	if len(cfg_next.Gr.Auth) < 20 {
		return errors.New("invalid gr_auth value")
	}

	if v, ok := appCfg.ValueOK("gr_mode"); ok {
		if v.String() == "multi-primary" {
			cfg_next.Gr.MultiPrimary = true
		} else {
			cfg_next.Gr.MultiPrimary = false
		}
	} else {
		return errors.New("invalid gr_mode value")
	}

	srvPortGen := pod.Pod.Replica.Ports.Get(3306)
	if srvPortGen == nil {
		return errors.New("port not found")
	}

	srvPortGr := pod.Pod.Replica.Ports.Get(3307)
	if srvPortGr == nil {
		return errors.New("port not found")
	}

	cfg_next.Gr.Enable = true

	cfg_next.Gr.Port = int(srvPortGen.HostPort)
	cfg_next.Gr.ServerId = int(pod.Pod.Replica.RepId + 1)
	cfg_next.Gr.BindAddress = pod.Pod.Replica.HostAddress(pod.Pod.Meta.ID)
	cfg_next.Gr.ReportHost = pod.Pod.Replica.HostAddress(pod.Pod.Meta.ID)

	//
	cfg_next.Gr.GroupName = idhash.HashUUID([]byte(pod.Pod.Meta.ID))
	cfg_next.Gr.LocalAddress = fmt.Sprintf("%s:%d", cfg_next.Gr.ReportHost, srvPortGr.HostPort)
	cfg_next.Gr.IpWhitelist = ""
	cfg_next.Gr.GroupSeeds = ""

	for i, v := range pod.Pod.Operate.Replicas {

		if i >= int(pod.Pod.Operate.ReplicaCap) {
			break
		}

		if cfg_next.Gr.IpWhitelist != "" {
			cfg_next.Gr.IpWhitelist += ","
			cfg_next.Gr.GroupSeeds += ","
		}

		cfg_next.Gr.IpWhitelist += v.HostAddress(pod.Pod.Meta.ID)

		srvPort := v.Ports.Get(3307)
		if srvPort == nil {
			return errors.New("port not found")
		}

		cfg_next.Gr.GroupSeeds += fmt.Sprintf("%s:%d", v.HostAddress(pod.Pod.Meta.ID), srvPort.HostPort)
	}

	// 10/8 prefix       (10.0.0.0 - 10.255.255.255) - Class A
	// 172.16/12 prefix  (172.16.0.0 - 172.31.255.255) - Class B
	// 192.168/16 prefix (192.168.0.0 - 192.168.255.255) - Class C
	// 127.0.0.1 - localhost for IPv4
	// cfg_next.Gr.IpWhitelist += ",192.168.38.88,192.168.3.160"

	if cfg_last.GrInited && reflect.DeepEqual(cfg_last.Gr, cfg_next.Gr) {
		return nil
	}

	//
	sets := map[string]interface{}{
		"server_port":             cfg_next.Gr.Port,
		"server_server_id":        cfg_next.Gr.ServerId,
		"server_bind_address":     cfg_next.Gr.BindAddress,
		"server_report_host":      cfg_next.Gr.ReportHost,
		"server_gr_group_name":    cfg_next.Gr.GroupName,
		"server_gr_ip_whitelist":  cfg_next.Gr.IpWhitelist,
		"server_gr_group_seeds":   cfg_next.Gr.GroupSeeds,
		"server_gr_local_address": cfg_next.Gr.LocalAddress,
		"server_gr_multi_primary": cfg_next.Gr.MultiPrimary,
	}

	if err := filerender.Render(mysql_gr_server_tpl, mysql_gr_server, 0644, sets); err != nil {
		return err
	}

	hlog.Printf("info", "setup %s ok", mysql_gr_server)

	return nil
}

func setupGrOpr(pod *inconf.PodConfigurator) error {

	if pod.Pod.Operate.ReplicaCap < 2 {
		return nil
	}

	app := pod.AppConfigurator("sysinner-mysql-gr")
	if app == nil {
		return nil
	}

	if app.AppSpec().Meta.ID != "sysinner-mysql-gr" {
		return nil
	}

	mu.Lock()
	defer mu.Unlock()

	var err error

	if !cfg_last.GrInited {

		sql := strings.Join([]string{
			"SET SQL_LOG_BIN=0;",
			fmt.Sprintf(`CREATE USER IF NOT EXISTS repl@'%%' IDENTIFIED BY '%s' REQUIRE SSL;`, cfg_last.Gr.Auth),
			// fmt.Sprintf("UPDATE USER SET password = password('%s') WHERE user = 'repl';", cfg_last.Gr.Auth),
			`GRANT REPLICATION SLAVE ON *.* TO repl@'%';`,
			"FLUSH PRIVILEGES;",
			"SET SQL_LOG_BIN=1;",
			fmt.Sprintf(`CHANGE MASTER TO MASTER_USER='repl', MASTER_PASSWORD="%s" FOR CHANNEL 'group_replication_recovery';`, cfg_last.Gr.Auth),
		}, " ")

		if err := conn_exec(sql); err != nil {
			hlog.Printf("warn", "setup gr user err %s", err.Error())
			return err
		}
		hlog.Printf("info", "sql/exec %s", sql)
		conn_close()

		cfg_last.GrInited = true
		confFlush()

		hlog.Printf("info", "setup gr user ok")
	}

	if !cfg_last.GrStarted {

		sql := []string{}

		if pod.Pod.Replica.RepId == 0 {

			sql = []string{
				"SET GLOBAL group_replication_bootstrap_group=ON;",
				"START GROUP_REPLICATION;",
				"SET GLOBAL group_replication_bootstrap_group=OFF;",
			}
		} else {
			time.Sleep(3e9)
			sql = []string{
				"START GROUP_REPLICATION;",
			}
		}

		err = conn_exec(strings.Join(sql, " "))
		if err != nil && !strings.Contains(err.Error(), "group is already running") {

			hlog.Printf("warn", "setup gr start GROUP_REPLICATION err %s, rep %d",
				err.Error(), pod.Pod.Replica.RepId)

			if pod.Pod.Replica.RepId > 0 &&
				(strings.Contains(err.Error(), "not configured properly to be an active member of the group") ||
					strings.Contains(err.Error(), "transactions not present in the group")) {
				time.Sleep(3e9)
				sql = []string{
					"STOP GROUP_REPLICATION;",
					"RESET MASTER;",
					"START GROUP_REPLICATION;",
				}
				err = conn_exec(strings.Join(sql, " "))
				if err != nil {

					hlog.Printf("warn", "setup gr retry start  GROUP_REPLICATION err %s, rep %d",
						err.Error(), pod.Pod.Replica.RepId)

					return err
				} else {
					hlog.Printf("info", "sql/exec %s", sql)
				}
				hlog.Printf("warn", "setup gr RESET MASTER, rep %d",
					pod.Pod.Replica.RepId)
			}
		} else {
			hlog.Printf("info", "sql/exec %s", sql)
		}

		hlog.Printf("info", "setup gr start GROUP_REPLICATION ok, rep %d", pod.Pod.Replica.RepId)

		cfg_last.GrStarted = true
	}

	return nil
}

func clean_runlock() {
	os.Remove(mysql_sock)
	os.Remove(mysql_pidfile)
}

func start() error {

	mu.Lock()
	defer mu.Unlock()

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

	if !cfg_last.Inited {
		return errors.New("No Init")
	}

	if cfg_last.RootAuth != "" {
		return nil
	}

	root_auth := idhash.RandHexString(32)
	if cfg_next.Gr.Enable {
		root_auth = cfg_next.Gr.Auth
	}

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
				"SET SQL_LOG_BIN=0;",
				`FLUSH PRIVILEGES;`,
				fmt.Sprintf(`CREATE USER IF NOT EXISTS 'root'@'localhost' IDENTIFIED BY '%s';`, root_auth),
				fmt.Sprintf(`SET PASSWORD FOR 'root'@'localhost' = PASSWORD('%s');`, root_auth),
				`GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION;`,
				`FLUSH PRIVILEGES;`,
				"SET SQL_LOG_BIN=1;",
			}, " ")

			if err = conn_exec(sql); err != nil {
				hlog.Printf("error", "init root pass err %s", err.Error())
			} else {
				hlog.Printf("info", "init root user ok, sql %s", sql)
				cfg_last.RootAuth = root_auth
				err = confFlush()
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

	hlog.Printf("info", "init_root_auth ok")

	cfg_last.RootAuth = root_auth
	err = confFlush()

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

		sql := strings.Join([]string{
			"SET SQL_LOG_BIN=0;",
			fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s;", cfg_next.Database.Name),
			"SET SQL_LOG_BIN=1;",
		}, " ")
		if err = conn_exec(sql); err != nil {
			return err
		}

		hlog.Printf("info", "create database %s ok, sql %s", cfg_next.Database.Name, sql)

		cfg_last.Database = cfg_next.Database
		err = confFlush()
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

			sql := strings.Join([]string{
				"SET SQL_LOG_BIN=0;",
				fmt.Sprintf(`DROP USER IF EXISTS '%s'@'%%';`, v.Name),
				fmt.Sprintf(`CREATE USER '%s'@'%%' IDENTIFIED BY '%s';`, v.Name, v.Auth),
				fmt.Sprintf(`GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%%' WITH GRANT OPTION;`, cfg_last.Database.Name, v.Name),
				"FLUSH PRIVILEGES;",
				"SET SQL_LOG_BIN=1;",
			}, " ")

			if err = conn_exec(sql); err != nil {
				return err
			}

			hlog.Printf("info", "create user %s ok, sql %s", v.Name, sql)

			cfg_last.UserSync(v)
			err = confFlush()
		}
	}

	return err
}

var (
	dbOpr mysql.Conn
)

func conn_exec(sql string) error {

	var err error

	for i := 0; i < 3; i++ {

		if dbOpr == nil {
			db := mysql.New("unix", "", mysql_sock, "root", cfg_last.RootAuth)
			if err = db.Connect(); err != nil {
				hlog.Printf("info", "conn err %s", err.Error())
				return err
			}
			dbOpr = db
		}

		// _, _, err = dbOpr.Query("SET SQL_LOG_BIN=0;")
		if err == nil {
			_, _, err = dbOpr.Query(sql)
			if err == nil {
				return nil
			}
		}

		dbOpr.Close()
		dbOpr = nil

		time.Sleep(3e9)
	}

	return err
}

func conn_close() {
	if dbOpr != nil {
		dbOpr.Close()
		dbOpr = nil
	}
}

func confFlush() error {
	return json.EncodeToFile(cfg_last, mysql_cnf_init, "  ")
}
