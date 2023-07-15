##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3869 and
# CentOS Errata and Security Advisory 2020:3869 respectively.
##

include('compat.inc');

if (description)
{
  script_id(143283);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2019-3695", "CVE-2019-3696");
  script_xref(name:"RHSA", value:"2020:3869");

  script_name(english:"CentOS 7 : pcp (CESA-2020:3869)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:3869 advisory.

  - pcp: Local privilege escalation in pcp spec file %post section (CVE-2019-3695)

  - pcp: Local privilege escalation in pcp spec file through migrate_tempdirs (CVE-2019-3696)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-October/012798.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5052ea8f");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/22.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/94.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(22, 94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2spark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-pcp2zabbix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-export-zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-import-collectl2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-import-ganglia2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-bcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-bind2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-bonding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-dbping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-ds389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-ds389log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-gpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-gpsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-infiniband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-lio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-lmsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-lustre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-lustrecomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-mic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-mounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-named");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-netfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-nfsclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-nvidia-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-perfevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-roomtemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-shping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-weblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-zimbra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-pmda-zswap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-system-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webapp-blinkenlights");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webapp-grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webapp-graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webapp-vector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-webjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcp-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-pcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-conf-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-devel-4.3.2-12.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'pcp-devel-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-doc-4.3.2-12.el7', 'release':'CentOS-7'},
    {'reference':'pcp-export-pcp2elasticsearch-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-export-pcp2graphite-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-export-pcp2influxdb-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-export-pcp2json-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-export-pcp2spark-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-export-pcp2xml-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-export-pcp2zabbix-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-export-zabbix-agent-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-gui-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-import-collectl2pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-import-ganglia2pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-import-iostat2pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-import-mrtg2pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-import-sar2pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-libs-4.3.2-12.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'pcp-libs-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-libs-devel-4.3.2-12.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'pcp-libs-devel-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-manager-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-activemq-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-apache-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-bash-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-bcc-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-bind2-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-bonding-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-cifs-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-cisco-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-dbping-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-dm-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-docker-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-ds389-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-ds389log-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-elasticsearch-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-gfs2-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-gluster-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-gpfs-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-gpsd-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-haproxy-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-infiniband-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-json-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-libvirt-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-lio-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-lmsensors-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-logger-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-lustre-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-lustrecomm-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-mailq-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-memcache-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-mic-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-mounts-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-mysql-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-named-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-netfilter-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-news-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-nfsclient-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-nginx-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-nvidia-gpu-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-oracle-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-pdns-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-perfevent-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-postfix-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-postgresql-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-prometheus-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-redis-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-roomtemp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-rpm-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-rsyslog-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-samba-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-sendmail-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-shping-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-slurm-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-smart-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-snmp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-summary-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-systemd-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-trace-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-unbound-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-vmware-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-weblog-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-zimbra-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-pmda-zswap-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-selinux-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-system-tools-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-testsuite-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-webapi-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'pcp-webapp-blinkenlights-4.3.2-12.el7', 'release':'CentOS-7'},
    {'reference':'pcp-webapp-grafana-4.3.2-12.el7', 'release':'CentOS-7'},
    {'reference':'pcp-webapp-graphite-4.3.2-12.el7', 'release':'CentOS-7'},
    {'reference':'pcp-webapp-vector-4.3.2-12.el7', 'release':'CentOS-7'},
    {'reference':'pcp-webjs-4.3.2-12.el7', 'release':'CentOS-7'},
    {'reference':'pcp-zeroconf-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'perl-PCP-LogImport-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'perl-PCP-LogSummary-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'perl-PCP-MMV-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'perl-PCP-PMDA-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'python-pcp-4.3.2-12.el7', 'cpu':'x86_64', 'release':'CentOS-7'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +
    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pcp / pcp-conf / pcp-devel / etc');
}
