##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1873-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(161653);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2020-8025");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1873-1");

  script_name(english:"SUSE SLES12 Security Update : pcp (SUSE-SU-2022:1873-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2022:1873-1 advisory.

  - A Incorrect Execution-Assigned Permissions vulnerability in the permissions package of SUSE Linux
    Enterprise Server 12-SP4, SUSE Linux Enterprise Server 15-LTSS, SUSE Linux Enterprise Server for SAP 15;
    openSUSE Leap 15.1, openSUSE Tumbleweed sets the permissions for some of the directories of the pcp
    package to unintended settings. This issue affects: SUSE Linux Enterprise Server 12-SP4 permissions
    versions prior to 20170707-3.24.1. SUSE Linux Enterprise Server 15-LTSS permissions versions prior to
    20180125-3.27.1. SUSE Linux Enterprise Server for SAP 15 permissions versions prior to 20180125-3.27.1.
    openSUSE Leap 15.1 permissions versions prior to 20181116-lp151.4.24.1. openSUSE Tumbleweed permissions
    versions prior to 20200624. (CVE-2020-8025)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1171883");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-May/011172.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?502fc143");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8025");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_gui2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_import1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_mmv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_trace2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpcp_web1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-pcp2graphite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-pcp2influxdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-export-zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-collectl2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-ganglia2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-bind2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-bonding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-dbping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-ds389");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-ds389log");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-elasticsearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-gfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-gpfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-gpsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-infiniband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-lio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-lmsensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-lustre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-lustrecomm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-mailq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-memcache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-mic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-mounts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-named");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-netfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-news");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-nfsclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-nutcracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-nvidia-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-pdns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-perfevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-roomtemp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-rsyslog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-shping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-summary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-weblog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-zimbra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-pmda-zswap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-system-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pcp-webapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-pcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libpcp-devel-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libpcp3-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libpcp_gui2-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libpcp_import1-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libpcp_mmv1-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libpcp_trace2-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libpcp_web1-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-conf-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-devel-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-doc-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-export-pcp2graphite-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-export-pcp2influxdb-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-export-zabbix-agent-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-gui-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-import-collectl2pcp-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-import-ganglia2pcp-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-import-iostat2pcp-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-import-mrtg2pcp-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-import-sar2pcp-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-manager-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-activemq-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-apache-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-bash-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-bind2-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-bonding-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-cifs-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-cisco-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-dbping-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-dm-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-docker-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-ds389-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-ds389log-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-elasticsearch-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-gfs2-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-gluster-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-gpfs-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-gpsd-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-infiniband-3.11.9-6.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-infiniband-3.11.9-6.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-kvm-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-libvirt-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-lio-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-lmsensors-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-logger-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-lustre-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-lustrecomm-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-mailq-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-memcache-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-mic-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-mounts-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-mysql-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-named-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-netfilter-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-news-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-nfsclient-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-nginx-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-nutcracker-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-nvidia-gpu-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-oracle-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-pdns-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-perfevent-3.11.9-6.17.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-perfevent-3.11.9-6.17.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-postfix-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-redis-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-roomtemp-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-rpm-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-rsyslog-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-samba-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-sendmail-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-shping-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-slurm-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-snmp-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-summary-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-systemd-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-trace-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-unbound-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-vmware-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-weblog-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-zimbra-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-pmda-zswap-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-system-tools-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'pcp-webapi-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'perl-PCP-LogImport-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'perl-PCP-LogSummary-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'perl-PCP-MMV-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'perl-PCP-PMDA-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'python-pcp-3.11.9-6.17.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5', 'sle-sdk-release-12.5', 'sles-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libpcp-devel / libpcp3 / libpcp_gui2 / libpcp_import1 / libpcp_mmv1 / etc');
}
