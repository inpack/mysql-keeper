project.name = los-mysql-keeper
project.version = 0.1.0-dev
project.vendor = lessos.com
project.homepage = https://code.hooto.com/lospack/los-mysql-keeper
project.groups = dev/db
project.description = automated configuration management for mysql

%build
PREFIX="{{.project__prefix}}"

mkdir -p {{.buildroot}}/{bin,log}

go build -ldflags "-w -s" -o {{.buildroot}}/bin/los-mysql-keeper keeper.go


%files
