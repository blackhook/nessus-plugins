##
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1561.
##

include('compat.inc');

if (description)
{
  script_id(142734);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/11");

  script_cve_id("CVE-2019-3695", "CVE-2019-3696");
  script_xref(name:"ALAS", value:"2020-1561");

  script_name(english:"Amazon Linux 2 : pcp (ALAS-2020-1561)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by
multiple vulnerabilities as referenced in the ALAS2-2020-1561 advisory.

  - A Improper Control of Generation of Code vulnerability in the packaging of pcp of SUSE Linux Enterprise
    High Performance Computing 15-ESPOS, SUSE Linux Enterprise High Performance Computing 15-LTSS, SUSE Linux
    Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for Development Tools 15-SP1,
    SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Server
    15-LTSS, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Software Development Kit 12-SP4,
    SUSE Linux Enterprise Software Development Kit 12-SP5; openSUSE Leap 15.1 allows the user pcp to run code
    as root by placing it into /var/log/pcp/configs.sh This issue affects: SUSE Linux Enterprise High
    Performance Computing 15-ESPOS pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise High Performance
    Computing 15-LTSS pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Module for Development Tools
    15 pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Module for Development Tools 15-SP1 pcp
    versions prior to 4.3.1-3.5.3. SUSE Linux Enterprise Module for Open Buildservice Development Tools 15 pcp
    versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Server 15-LTSS pcp versions prior to 3.11.9-5.8.1.
    SUSE Linux Enterprise Server for SAP 15 pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Software
    Development Kit 12-SP4 pcp versions prior to 3.11.9-6.14.1. SUSE Linux Enterprise Software Development Kit
    12-SP5 pcp versions prior to 3.11.9-6.14.1. openSUSE Leap 15.1 pcp versions prior to 4.3.1-lp151.2.3.1.
    (CVE-2019-3695)

  - A Improper Limitation of a Pathname to a Restricted Directory vulnerability in the packaging of pcp of
    SUSE Linux Enterprise High Performance Computing 15-ESPOS, SUSE Linux Enterprise High Performance
    Computing 15-LTSS, SUSE Linux Enterprise Module for Development Tools 15, SUSE Linux Enterprise Module for
    Development Tools 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE
    Linux Enterprise Server 15-LTSS, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Software
    Development Kit 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5; openSUSE Leap 15.1 allows
    local user pcp to overwrite arbitrary files with arbitrary content. This issue affects: SUSE Linux
    Enterprise High Performance Computing 15-ESPOS pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise
    High Performance Computing 15-LTSS pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Module for
    Development Tools 15 pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Module for Development
    Tools 15-SP1 pcp versions prior to 4.3.1-3.5.3. SUSE Linux Enterprise Module for Open Buildservice
    Development Tools 15 pcp versions prior to 3.11.9-5.8.1. SUSE Linux Enterprise Server 15-LTSS pcp versions
    prior to 3.11.9-5.8.1. SUSE Linux Enterprise Server for SAP 15 pcp versions prior to 3.11.9-5.8.1. SUSE
    Linux Enterprise Software Development Kit 12-SP4 pcp versions prior to 3.11.9-6.14.1. SUSE Linux
    Enterprise Software Development Kit 12-SP5 pcp versions prior to 3.11.9-6.14.1. openSUSE Leap 15.1 pcp
    versions prior to 4.3.1-lp151.2.3.1. (CVE-2019-3696)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1561.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3695");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2019-3696");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update pcp' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-export-pcp2elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-export-pcp2graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-export-pcp2influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-export-pcp2json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-export-pcp2spark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-export-pcp2xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-export-pcp2zabbix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-export-zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-import-collectl2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-import-ganglia2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-bind2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-bonding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-dbping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-ds389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-ds389log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-gpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-gpsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-infiniband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-lio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-lmsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-lustre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-lustrecomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-mic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-mounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-named");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-netfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-nfsclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-nvidia-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-perfevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-roomtemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-shping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-weblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-zimbra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-pmda-zswap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-system-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-webapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-webapp-blinkenlights");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-webapp-grafana");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-webapp-graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-webapp-vector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-webjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pcp-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-pcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

pkgs = [
    {'reference':'pcp-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-conf-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-conf-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-conf-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-debuginfo-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-debuginfo-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-debuginfo-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-devel-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-devel-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-devel-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-doc-4.3.2-12.amzn2.0.1', 'release':'AL2'},
    {'reference':'pcp-export-pcp2elasticsearch-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2elasticsearch-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-export-pcp2elasticsearch-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2graphite-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2graphite-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-export-pcp2graphite-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2influxdb-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2influxdb-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-export-pcp2influxdb-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2json-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2json-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-export-pcp2json-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2spark-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2spark-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-export-pcp2spark-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2xml-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2xml-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-export-pcp2xml-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2zabbix-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-export-pcp2zabbix-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-export-pcp2zabbix-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-export-zabbix-agent-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-export-zabbix-agent-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-export-zabbix-agent-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-gui-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-gui-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-gui-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-import-collectl2pcp-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-import-collectl2pcp-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-import-collectl2pcp-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-import-ganglia2pcp-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-import-ganglia2pcp-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-import-ganglia2pcp-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-import-iostat2pcp-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-import-iostat2pcp-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-import-iostat2pcp-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-import-mrtg2pcp-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-import-mrtg2pcp-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-import-mrtg2pcp-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-import-sar2pcp-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-import-sar2pcp-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-import-sar2pcp-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-libs-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-libs-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-libs-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-libs-devel-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-libs-devel-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-libs-devel-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-manager-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-manager-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-manager-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-activemq-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-activemq-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-activemq-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-apache-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-apache-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-apache-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-bash-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-bash-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-bash-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-bind2-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-bind2-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-bind2-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-bonding-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-bonding-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-bonding-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-cifs-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-cifs-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-cifs-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-cisco-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-cisco-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-cisco-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-dbping-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-dbping-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-dbping-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-dm-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-dm-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-dm-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-docker-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-docker-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-docker-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-ds389-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-ds389-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-ds389-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-ds389log-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-ds389log-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-ds389log-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-elasticsearch-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-elasticsearch-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-elasticsearch-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-gfs2-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-gfs2-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-gfs2-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-gluster-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-gluster-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-gluster-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-gpfs-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-gpfs-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-gpfs-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-gpsd-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-gpsd-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-gpsd-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-haproxy-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-haproxy-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-haproxy-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-infiniband-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-infiniband-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-infiniband-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-json-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-json-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-json-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-libvirt-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-libvirt-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-libvirt-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-lio-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-lio-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-lio-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-lmsensors-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-lmsensors-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-lmsensors-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-logger-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-logger-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-logger-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-lustre-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-lustre-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-lustre-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-lustrecomm-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-lustrecomm-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-lustrecomm-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-mailq-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-mailq-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-mailq-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-memcache-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-memcache-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-memcache-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-mic-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-mic-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-mic-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-mounts-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-mounts-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-mounts-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-mysql-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-mysql-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-mysql-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-named-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-named-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-named-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-netfilter-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-netfilter-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-netfilter-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-news-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-news-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-news-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-nfsclient-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-nfsclient-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-nfsclient-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-nginx-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-nginx-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-nginx-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-nvidia-gpu-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-nvidia-gpu-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-nvidia-gpu-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-oracle-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-oracle-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-oracle-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-pdns-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-pdns-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-pdns-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-perfevent-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-perfevent-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-perfevent-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-postfix-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-postfix-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-postfix-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-postgresql-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-postgresql-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-postgresql-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-prometheus-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-prometheus-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-prometheus-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-redis-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-redis-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-redis-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-roomtemp-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-roomtemp-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-roomtemp-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-rpm-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-rpm-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-rpm-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-rsyslog-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-rsyslog-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-rsyslog-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-samba-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-samba-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-samba-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-sendmail-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-sendmail-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-sendmail-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-shping-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-shping-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-shping-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-slurm-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-slurm-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-slurm-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-smart-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-smart-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-smart-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-snmp-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-snmp-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-snmp-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-summary-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-summary-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-summary-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-systemd-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-systemd-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-systemd-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-trace-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-trace-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-trace-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-unbound-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-unbound-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-unbound-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-vmware-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-vmware-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-vmware-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-weblog-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-weblog-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-weblog-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-zimbra-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-zimbra-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-zimbra-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-pmda-zswap-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-pmda-zswap-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-pmda-zswap-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-selinux-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-selinux-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-selinux-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-system-tools-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-system-tools-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-system-tools-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-testsuite-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-testsuite-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-testsuite-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-webapi-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-webapi-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-webapi-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'pcp-webapp-blinkenlights-4.3.2-12.amzn2.0.1', 'release':'AL2'},
    {'reference':'pcp-webapp-grafana-4.3.2-12.amzn2.0.1', 'release':'AL2'},
    {'reference':'pcp-webapp-graphite-4.3.2-12.amzn2.0.1', 'release':'AL2'},
    {'reference':'pcp-webapp-vector-4.3.2-12.amzn2.0.1', 'release':'AL2'},
    {'reference':'pcp-webjs-4.3.2-12.amzn2.0.1', 'release':'AL2'},
    {'reference':'pcp-zeroconf-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'pcp-zeroconf-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'pcp-zeroconf-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-PCP-LogImport-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-PCP-LogImport-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-PCP-LogImport-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-PCP-LogSummary-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-PCP-LogSummary-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-PCP-LogSummary-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-PCP-MMV-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-PCP-MMV-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-PCP-MMV-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'perl-PCP-PMDA-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'perl-PCP-PMDA-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'perl-PCP-PMDA-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'},
    {'reference':'python-pcp-4.3.2-12.amzn2.0.1', 'cpu':'aarch64', 'release':'AL2'},
    {'reference':'python-pcp-4.3.2-12.amzn2.0.1', 'cpu':'i686', 'release':'AL2'},
    {'reference':'python-pcp-4.3.2-12.amzn2.0.1', 'cpu':'x86_64', 'release':'AL2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcp / pcp-conf / pcp-debuginfo / etc");
}