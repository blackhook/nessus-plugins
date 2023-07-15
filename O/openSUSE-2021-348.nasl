#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-348.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(146888);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/01");

  script_name(english:"openSUSE Security Update : pcp (openSUSE-2021-348)");
  script_summary(english:"Check for the openSUSE-2021-348 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for pcp fixes the following issues :

  - Drop unnecessary %pre/%post recursive chown calls
    (bsc#1152533)

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1152533"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcp packages.");
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp_gui2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp_gui2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp_import1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp_import1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp_mmv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp_mmv1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp_trace2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp_trace2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp_web1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp_web1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-export-pcp2elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-export-pcp2graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-export-pcp2influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-export-pcp2json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-export-pcp2spark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-export-pcp2xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-export-pcp2zabbix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-export-zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-export-zabbix-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-gui-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-import-collectl2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-import-collectl2pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-import-ganglia2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-manager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-apache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-bash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-bind2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-bonding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-cifs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-cisco-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-dbping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-dm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-ds389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-ds389log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-gfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-gpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-gpsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-infiniband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-infiniband-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-lmsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-logger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-lustre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-lustrecomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-lustrecomm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-mailq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-mic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-mounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-mounts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-named");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-netfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-nfsclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-nutcracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-nvidia-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-nvidia-gpu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-papi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-papi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-perfevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-perfevent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-roomtemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-roomtemp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-sendmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-shping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-shping-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-smart-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-summary-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-weblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-weblog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-zimbra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-pmda-zswap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-system-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-system-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-testsuite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-webapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-webapi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-LogImport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-MMV-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-PMDA-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libpcp-devel-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp3-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp3-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp_gui2-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp_gui2-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp_import1-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp_import1-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp_mmv1-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp_mmv1-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp_trace2-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp_trace2-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp_web1-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpcp_web1-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-conf-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-debugsource-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-devel-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-devel-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-export-pcp2elasticsearch-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-export-pcp2graphite-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-export-pcp2influxdb-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-export-pcp2json-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-export-pcp2spark-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-export-pcp2xml-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-export-pcp2zabbix-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-export-zabbix-agent-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-export-zabbix-agent-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-gui-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-gui-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-import-collectl2pcp-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-import-collectl2pcp-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-import-ganglia2pcp-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-import-iostat2pcp-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-import-mrtg2pcp-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-import-sar2pcp-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-manager-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-manager-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-activemq-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-apache-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-apache-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-bash-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-bash-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-bind2-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-bonding-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-cifs-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-cifs-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-cisco-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-cisco-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-dbping-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-dm-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-dm-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-docker-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-docker-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-ds389-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-ds389log-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-elasticsearch-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-gfs2-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-gfs2-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-gluster-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-gpfs-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-gpsd-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-haproxy-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-infiniband-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-infiniband-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-json-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-lmsensors-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-logger-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-logger-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-lustre-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-lustrecomm-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-lustrecomm-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-mailq-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-mailq-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-memcache-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-mic-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-mounts-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-mounts-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-mysql-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-named-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-netfilter-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-news-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-nfsclient-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-nginx-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-nutcracker-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-nvidia-gpu-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-nvidia-gpu-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-oracle-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-papi-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-papi-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-pdns-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-perfevent-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-perfevent-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-postfix-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-prometheus-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-redis-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-roomtemp-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-roomtemp-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-rpm-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-rpm-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-rsyslog-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-samba-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-sendmail-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-sendmail-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-shping-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-shping-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-slurm-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-smart-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-smart-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-snmp-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-summary-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-summary-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-systemd-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-systemd-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-trace-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-trace-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-unbound-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-vmware-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-weblog-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-weblog-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-zimbra-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-pmda-zswap-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-system-tools-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-system-tools-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-testsuite-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-testsuite-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-webapi-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-webapi-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"pcp-zeroconf-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-PCP-LogImport-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-PCP-LogImport-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-PCP-LogSummary-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-PCP-MMV-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-PCP-MMV-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-PCP-PMDA-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-PCP-PMDA-debuginfo-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-pcp-4.3.1-lp152.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-pcp-debuginfo-4.3.1-lp152.5.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpcp-devel / libpcp3 / libpcp3-debuginfo / libpcp_gui2 / etc");
}
