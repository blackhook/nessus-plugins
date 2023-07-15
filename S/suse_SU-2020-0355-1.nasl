#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0355-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(133594);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2019-3695", "CVE-2019-3696");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : pcp (SUSE-SU-2020:0355-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for pcp fixes the following issues :

Security issue fixed :

CVE-2019-3695: Fixed a local privilege escalation of the pcp user
during package update (bsc#1152763).

Non-security issue fixed :

Fixed an dependency issue with pcp2csv (bsc#1129991).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1129991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1152763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1153921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3695/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3696/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200355-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddb428cd"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-355=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Development-Tools-15-SP1-2020-355=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3695");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_gui2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_gui2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_import1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_import1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_mmv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_mmv1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_trace2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_trace2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_web1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_web1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-pcp2elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-pcp2graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-pcp2influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-pcp2json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-pcp2spark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-pcp2xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-pcp2zabbix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-zabbix-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-gui-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-collectl2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-collectl2pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-ganglia2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-manager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-apache-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-bash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-bind2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-bonding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-cifs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-cisco-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-dbping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-dm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-ds389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-ds389log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-gfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-gpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-gpsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-infiniband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-infiniband-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-lmsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-logger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-lustre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-lustrecomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-lustrecomm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-mailq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-mic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-mounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-mounts-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-named");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-netfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-nfsclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-nutcracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-nvidia-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-nvidia-gpu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-papi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-papi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-perfevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-perfevent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-roomtemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-roomtemp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-sendmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-shping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-shping-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-smart-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-summary-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-weblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-weblog-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-zimbra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-zswap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-system-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-system-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-testsuite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-webapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-webapi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-zeroconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-LogImport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-MMV-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-PMDA-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-infiniband-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-infiniband-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-papi-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-papi-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-perfevent-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-perfevent-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp-devel-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp3-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp3-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp_gui2-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp_gui2-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp_import1-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp_import1-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp_mmv1-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp_mmv1-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp_trace2-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp_trace2-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp_web1-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libpcp_web1-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-conf-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-debugsource-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-devel-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-devel-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-export-pcp2elasticsearch-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-export-pcp2graphite-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-export-pcp2influxdb-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-export-pcp2json-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-export-pcp2spark-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-export-pcp2xml-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-export-pcp2zabbix-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-export-zabbix-agent-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-export-zabbix-agent-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-gui-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-gui-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-import-collectl2pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-import-collectl2pcp-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-import-ganglia2pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-import-iostat2pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-import-mrtg2pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-import-sar2pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-manager-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-manager-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-activemq-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-apache-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-apache-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-bash-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-bash-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-bind2-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-bonding-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-cifs-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-cifs-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-cisco-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-cisco-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-dbping-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-dm-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-dm-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-docker-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-docker-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-ds389-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-ds389log-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-elasticsearch-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-gfs2-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-gfs2-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-gluster-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-gpfs-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-gpsd-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-haproxy-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-json-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-lmsensors-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-logger-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-logger-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-lustre-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-lustrecomm-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-lustrecomm-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-mailq-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-mailq-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-memcache-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-mic-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-mounts-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-mounts-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-mysql-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-named-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-netfilter-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-news-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-nfsclient-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-nginx-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-nutcracker-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-nvidia-gpu-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-nvidia-gpu-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-oracle-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-pdns-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-postfix-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-prometheus-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-redis-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-roomtemp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-roomtemp-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-rpm-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-rpm-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-rsyslog-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-samba-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-sendmail-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-sendmail-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-shping-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-shping-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-slurm-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-smart-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-smart-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-snmp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-summary-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-summary-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-systemd-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-systemd-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-trace-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-trace-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-unbound-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-vmware-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-weblog-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-weblog-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-zimbra-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-pmda-zswap-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-system-tools-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-system-tools-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-testsuite-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-testsuite-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-webapi-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-webapi-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"pcp-zeroconf-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PCP-LogImport-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PCP-LogImport-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PCP-LogSummary-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PCP-MMV-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PCP-MMV-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PCP-PMDA-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"perl-PCP-PMDA-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-pcp-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-infiniband-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-infiniband-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-papi-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-papi-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-perfevent-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"pcp-pmda-perfevent-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp-devel-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp3-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp3-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp_gui2-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp_gui2-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp_import1-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp_import1-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp_mmv1-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp_mmv1-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp_trace2-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp_trace2-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp_web1-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libpcp_web1-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-conf-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-debugsource-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-devel-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-devel-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-export-pcp2elasticsearch-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-export-pcp2graphite-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-export-pcp2influxdb-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-export-pcp2json-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-export-pcp2spark-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-export-pcp2xml-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-export-pcp2zabbix-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-export-zabbix-agent-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-export-zabbix-agent-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-gui-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-gui-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-import-collectl2pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-import-collectl2pcp-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-import-ganglia2pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-import-iostat2pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-import-mrtg2pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-import-sar2pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-manager-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-manager-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-activemq-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-apache-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-apache-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-bash-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-bash-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-bind2-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-bonding-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-cifs-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-cifs-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-cisco-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-cisco-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-dbping-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-dm-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-dm-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-docker-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-docker-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-ds389-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-ds389log-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-elasticsearch-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-gfs2-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-gfs2-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-gluster-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-gpfs-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-gpsd-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-haproxy-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-json-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-lmsensors-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-logger-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-logger-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-lustre-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-lustrecomm-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-lustrecomm-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-mailq-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-mailq-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-memcache-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-mic-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-mounts-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-mounts-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-mysql-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-named-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-netfilter-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-news-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-nfsclient-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-nginx-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-nutcracker-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-nvidia-gpu-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-nvidia-gpu-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-oracle-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-pdns-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-postfix-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-prometheus-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-redis-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-roomtemp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-roomtemp-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-rpm-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-rpm-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-rsyslog-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-samba-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-sendmail-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-sendmail-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-shping-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-shping-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-slurm-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-smart-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-smart-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-snmp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-summary-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-summary-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-systemd-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-systemd-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-trace-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-trace-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-unbound-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-vmware-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-weblog-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-weblog-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-zimbra-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-pmda-zswap-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-system-tools-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-system-tools-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-testsuite-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-testsuite-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-webapi-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-webapi-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"pcp-zeroconf-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PCP-LogImport-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PCP-LogImport-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PCP-LogSummary-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PCP-MMV-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PCP-MMV-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PCP-PMDA-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"perl-PCP-PMDA-debuginfo-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-pcp-4.3.1-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-pcp-debuginfo-4.3.1-3.5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcp");
}
