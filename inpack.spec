[project]
name = mysql-keeper
version = 0.9.0
vendor = sysinner.com
homepage = http://www.sysinner.com
groups = dev/db
description = configuration management tool for mysql

%build
PREFIX="{{.project__prefix}}"

mkdir -p {{.buildroot}}/{bin,log}

go build -ldflags "-w -s" -o {{.buildroot}}/bin/mysql-keeper main.go


%files
misc/
