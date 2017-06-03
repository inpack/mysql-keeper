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
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"code.hooto.com/lessos/loscore/losapi"
	"github.com/lessos/lessgo/crypto/idhash"
	"github.com/lessos/lessgo/encoding/json"
	"github.com/lessos/lessgo/types"
	"github.com/ziutek/mymysql/mysql"
	_ "github.com/ziutek/mymysql/native"
)

var (
	pod_inst              = "/home/action/.los/pod_instance.json"
	mysql_prefix          = "/home/action/apps/mysql57"
	mysql_datadir         = mysql_prefix + "/data"
	mysql_bin_mysql       = mysql_prefix + "/bin/mysql57"
	mysql_bin_mysqld      = mysql_prefix + "/bin/mysql57d"
	mysql_bin_mysqladmin  = mysql_prefix + "/bin/mysql57admin"
	mysql_pidfile         = mysql_prefix + "/run/mysql.pid"
	mysql_sock            = mysql_prefix + "/run/mysql.sock"
	mysql_conf_init       = mysql_prefix + "/etc/init_option.json"
	mysql_conf_main       = mysql_prefix + "/etc/my.cnf"
	mysql_conf_main_tpl   = mysql_prefix + "/etc/my.cnf.default"
	mysql_conf_server     = mysql_prefix + "/etc/my.cnf.d/server.cnf"
	mysql_conf_server_tpl = mysql_prefix + "/etc/my.server.cnf.default"
	pod_inst_updated      time.Time
	mu                    sync.Mutex
	cfg_mu                sync.Mutex
	cfg_last              EnvConfig
	cfg_next              EnvConfig
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
	Ram int64 `json:"ram"`
	Cpu int64 `json:"cpu"`
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
		return
	}
	fpbin.Close()

	var (
		tstart = time.Now()
		inst   losapi.Pod
	)
	cfg_next = EnvConfig{}

	//
	{
		fp, err := os.Open(pod_inst)
		if err != nil {
			return
		}
		defer fp.Close()

		st, err := fp.Stat()
		if err != nil {
			return
		}

		if !st.ModTime().After(pod_inst_updated) {
			return
		}

		//
		bs, err := ioutil.ReadAll(fp)
		if err != nil {
			return
		}

		if err := json.Decode(bs, &inst); err != nil {
			return
		}

		if inst.Spec == nil ||
			len(inst.Spec.Boxes) == 0 ||
			inst.Spec.Boxes[0].Resources == nil {
			return
		}

		if inst.Spec.Boxes[0].Resources.MemLimit > 0 {
			cfg_next.Resource.Ram = inst.Spec.Boxes[0].Resources.MemLimit
		}
		if inst.Spec.Boxes[0].Resources.CpuLimit > 0 {
			cfg_next.Resource.Cpu = inst.Spec.Boxes[0].Resources.CpuLimit
		}
	}

	//
	var option *losapi.AppOption
	{
		for _, app := range inst.Apps {

			if app.Spec.Meta.Name != "mysql57" {
				continue
			}

			option = app.Operate.Options.Get("cfg/mysql")
			if option != nil {
				break
			}
		}

		if option == nil {
			return
		}

		if v, ok := option.Items.Get("db_name"); ok {
			cfg_next.Database = EnvConfigDatabase{
				Name: v.String(),
			}
		} else {
			return
		}

		if v, ok := option.Items.Get("db_user"); ok {

			vp, ok := option.Items.Get("db_auth")
			if !ok {
				return
			}

			cfg_next.UserSync(EnvConfigUser{
				Name: v.String(),
				Auth: vp.String(),
			})
		} else {
			return
		}
	}

	//
	if cfg_next.Resource.Ram < 128*losapi.ByteMB {
		return
	}

	//
	if cfg_last.Database.Name == "" {
		json.DecodeFile(mysql_conf_init, &cfg_last)
	}

	if err := init_cnf(); err != nil {
		return
	}

	//
	if err := init_datadir(); err != nil {
		return
	}

	if cfg_last.Resource.Ram != cfg_next.Resource.Ram {
		if err := restart(); err != nil {
			return
		}
		cfg_last.Resource.Ram = cfg_next.Resource.Ram
		cfg_last.Resource.Cpu = cfg_next.Resource.Cpu

	} else {

		if err := start(); err != nil {
			return
		}
	}

	if err := init_root_auth(); err != nil {
		fmt.Println("init_root_auth", err)
		return
	}

	if err := init_db(); err != nil {
		fmt.Println("init_db", err)
		return
	}

	if err := init_user(); err != nil {
		fmt.Println("init_user", err)
		return
	}

	pod_inst_updated = time.Now()

	fmt.Println("time", time.Since(tstart))
}

func file_render(dst_file, src_file string, sets map[string]string) error {

	fpsrc, err := os.Open(src_file)
	if err != nil {
		return err
	}
	defer fpsrc.Close()

	//
	src, err := ioutil.ReadAll(fpsrc)
	if err != nil {
		return err
	}

	//
	tpl, err := template.New("s").Parse(string(src))
	if err != nil {
		return err
	}

	var dst bytes.Buffer
	if err := tpl.Execute(&dst, sets); err != nil {
		return err
	}

	fpdst, err := os.OpenFile(dst_file, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer fpdst.Close()

	fpdst.Seek(0, 0)
	fpdst.Truncate(0)

	_, err = fpdst.Write(dst.Bytes())

	fmt.Println("file_render", dst_file, src_file)

	return err
}

func init_cnf() error {

	if cfg_last.Inited && cfg_last.Resource.Ram == cfg_next.Resource.Ram {
		return nil
	}

	//
	ram := int(cfg_next.Resource.Ram / losapi.ByteMB)
	sets := map[string]string{
		"project_prefix":                 mysql_prefix,
		"env_ram_size":                   fmt.Sprintf("%dM", ram),
		"server_key_buffer_size":         fmt.Sprintf("%dM", ram/4),
		"server_query_cache_size":        fmt.Sprintf("%dM", ram/8),
		"server_innodb_buffer_pool_size": fmt.Sprintf("%dM", ram/4),
	}

	if !cfg_last.Inited || cfg_last.Resource.Ram != cfg_next.Resource.Ram {

		if err := file_render(mysql_conf_server, mysql_conf_server_tpl, sets); err != nil {
			return err
		}
	}

	if !cfg_last.Inited {

		if err := file_render(mysql_conf_main, mysql_conf_main_tpl, sets); err != nil {
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

	if cfg_next.RootAuth == "" {
		return errors.New("No Root Password Setup")
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
		fmt.Println("initialize-insecure server", err)
	}

	if err == nil {
		cfg_last.Inited = true
		err = json.EncodeToFile(cfg_last, mysql_conf_init, "  ")
	}

	return err
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

	// _, err := exec.Command(mysql_bin_mysqld, ">", "/dev/null", "2>&1", "&").Output()
	_, err := exec.Command("/bin/sh", "-c", mysql_bin_mysqld+" > /dev/null 2>&1 &").Output()
	time.Sleep(1e9)
	fmt.Println("start mysqld", err)

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
		_, err = exec.Command("kill", "-s", "HUP", strconv.Itoa(pid)).Output()
		fmt.Println("kill HUP", err)

	} else {
		// _, err = exec.Command(mysql_bin_mysqld, ">", "/dev/null", "2>&1", "&").Output()
		_, err := exec.Command("/bin/sh", "-c", mysql_bin_mysqld+" > /dev/null 2>&1 &").Output()
		time.Sleep(1e9)
		fmt.Println("start mysqld", err)
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

	_, err := exec.Command(mysql_bin_mysqladmin,
		"-u", "root",
		"password", root_auth,
		"--socket="+mysql_sock,
	).Output()

	fmt.Println("init root password", err)

	if err == nil {
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

		_, err = exec.Command(mysql_bin_mysqladmin,
			"create", cfg_next.Database.Name,
			"--user=root",
			"--password="+cfg_last.RootAuth,
			"--socket="+mysql_sock,
		).Output()

		fmt.Println("create database", cfg_next.Database.Name, err)

		if err != nil {
			return err
		}

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

			fmt.Println("create user", v.Name)

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
		fmt.Println("conn err", err)
		return err
	}

	defer db.Close()

	_, _, err = db.Query(sql)

	return err
}
