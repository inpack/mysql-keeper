[project]
name = sysinner-mysql
version = 0.1.2-dev
vendor = sysinner.com
homepage = http://www.sysinner.com
groups = dev/db
description = automated configuration management for mysql

%build
PREFIX="{{.project__prefix}}"

mkdir -p {{.buildroot}}/{bin,log}

go build -ldflags "-w -s" -o {{.buildroot}}/bin/sysinner-mysql main.go


%files
