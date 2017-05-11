project.name = mysql57
project.version = 5.7.18
project.vendor = mysql.com
project.homepage = https://www.mysql.com
project.groups = dev/db
project.description = The world's most popular open source database

%build
PREFIX="{{.project__prefix}}"

mkdir -p {{.buildroot}}/{bin,etc/my.cnf.d,data,lib64/mysql/plugin,files,run,log}

go build -ldflags "-w -s" -o {{.buildroot}}/bin/keeper keeper.go

install misc/etc/my.cnf.default {{.buildroot}}/etc/my.cnf.default
install misc/etc/my.server.cnf.default {{.buildroot}}/etc/my.server.cnf.default

cd deps/mysql-server
cmake . -DWITH_BOOST=../boost_1_59_0 \
  -DCMAKE_INSTALL_PREFIX=$PREFIX \
  -DINSTALL_SBINDIR=bin \
  -DMYSQL_DATADIR=$PREFIX/data \
  -DSYSCONFDIR=$PREFIX/etc \
  -DMYSQL_UNIX_ADDR=$PREFIX/run/mysql.sock \
  -DWITH_INNODB_MEMCACHED=0 \
  -DWITH_EMBEDDED_SERVER=0 \
  -DDEFAULT_CHARSET=utf8 \
  -DWITH_INNOBASE_STORAGE_ENGINE=1 \
  -DWITH_MyISAM_STORAGE_ENGINE=1 \
  -DWITH_MEMORY_STORAGE_ENGINE=1 \
  -DWITH_CSV_STORAGE_ENGINE=1 \
  -DWITH_PERFORMANCE_SCHEMA_STORAGE_ENGINE=1 \
  -DWITHOUT_FEDERATED_STORAGE_ENGINE=1 \
  -DWITHOUT_MRG_MYISAM_STORAGE_ENGINE=1 \
  -DWITHOUT_BLACKHOLE_STORAGE_ENGINE=1 \
  -DWITHOUT_ARCHIVE_STORAGE_ENGINE=1 \
  -DDEFAULT_COLLATION=utf8_general_ci \
  -DMYSQL_USER=action

make mysql -j3
make mysqld -j3
make mysqladmin -j3
make connection_control -j3


strip -s sql/mysqld
install sql/mysqld {{.buildroot}}/bin/mysql57d

strip -s client/mysql
install client/mysql {{.buildroot}}/bin/mysql57

strip -s client/mysqladmin
install client/mysqladmin {{.buildroot}}/bin/mysql57admin

strip -s plugin/connection_control/connection_control.so
install plugin/connection_control/connection_control.so {{.buildroot}}/lib64/mysql/plugin/

rsync -av sql/share/* {{.buildroot}}/share/

%files
