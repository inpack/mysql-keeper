[project]
name = sysinner-mysql
version = 0.2.2
vendor = sysinner.com
homepage = http://www.sysinner.com
groups = dev/db
description = configuration management tool for mysql

%build
PREFIX="{{.project__prefix}}"

mkdir -p {{.buildroot}}/{bin,log}

go build -ldflags "-w -s" -o {{.buildroot}}/bin/sysinner-mysql main.go


%files
