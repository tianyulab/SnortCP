#!/bin/bash

# 1.定义变量

SNORT_VERSION=2.9.11.1
DAQ_VERSION=2.0.6
echo "Installing $SNORT_VERSION"

# 2.安装依赖软件包

echo "nameserver 9.9.9.9" > /etc/resolv.conf

echo "安装依赖软件包"
apt-get update -y && apt-get install -y \
    build-essential make flex bison \
    libpcap-dev libpcre3-dev \
    libcap-ng-dev libdumbnet-dev \
    zlib1g-dev liblzma-dev openssl libssl-dev \
    libnghttp2-dev wget python-pip && ldconfig

# 3.安装DAQ

echo "安装DAQ"
mkdir -p /src/snort-${SNORT_VERSION} && mkdir -p /etc/snort/rules/iplists && mkdir /etc/snort/preproc_rules && \
    mkdir /etc/snort/so_rules && mkdir -p /var/log/snort/archived_logs

cd /src
wget https://www.snort.org/downloads/archive/snort/daq-${DAQ_VERSION}.tar.gz
tar -zxf daq-${DAQ_VERSION}.tar.gz && cd daq-${DAQ_VERSION} && ./configure && make && make install && cd /src

# 4.安装Snort

echo "安装Snort"
groupadd snort && useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort

wget https://www.snort.org/downloads/archive/snort/snort-${SNORT_VERSION}.tar.gz
tar -zxf snort-${SNORT_VERSION}.tar.gz -C snort-${SNORT_VERSION} --strip-components=1 && \
    cd /src/snort-${SNORT_VERSION} && ./configure --enable-sourcefire && make -j $(nproc) && make install && \
    mkdir /usr/local/lib/snort_dynamicrules && ldconfig && cd /src
cp -t /etc/snort/ /src/snort-${SNORT_VERSION}/etc/attribute_table.dtd \
    /src/snort-${SNORT_VERSION}/etc/classification.config /src/snort-${SNORT_VERSION}/etc/file_magic.conf \
    /src/snort-${SNORT_VERSION}/etc/gen-msg.map /src/snort-${SNORT_VERSION}/etc/reference.config \
    /src/snort-${SNORT_VERSION}/etc/threshold.conf /src/snort-${SNORT_VERSION}/etc/unicode.map

## 设置权限
echo "设置权限"
chmod -R 5775 /etc/snort
chmod -R 5775 /var/log/snort
chmod -R 5775 /var/log/snort/archived_logs
chmod -R 5775 /etc/snort/so_rules
chmod -R 5775 /usr/local/lib/snort_dynamicrules
chown -R snort:snort /etc/snort
chown -R snort:snort /var/log/snort
chown -R snort:snort /usr/local/lib/snort_dynamicrules

# 5.配置Snort.conf

echo "配置Snort.conf"
wget https://github.com/tianyulab/SnortCP/blob/master/Config/snort.conf -O /etc/snort/snort.conf
# ipvar HOME_NET [10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]
# ipvar EXTERNAL_NET !$HOME_NET
# include $RULE_PATH/local.rules
# include $RULE_PATH/ET-all-snort.rules
# sed -i "s/include \$RULE\_PATH/#include \$RULE\_PATH/" /etc/snort/snort.conf

# 6.下载Snort规则

echo "下载Snort规则"
apt -y install python-pip && pip install idstools
/usr/local/bin/idstools-rulecat --url https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz -o /etc/snort/rules/ --merged /etc/snort/rules/ET-all-snort.rules

# 7.测试
echo 'alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:10000001; rev:001;)' >> /etc/snort/rules/local.rules

echo "使用以下命令进行测试"
echo "snort -A console -k none -i eth0 -u snort -g snort -c /etc/snort/snort.conf"
echo "ping -c1 g.cn"
