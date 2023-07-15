#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3725-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(166535);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2020-14004", "CVE-2020-29663", "CVE-2021-37698");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3725-1");

  script_name(english:"SUSE SLES12 Security Update : icinga2 (SUSE-SU-2022:3725-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2022:3725-1 advisory.

  - An issue was discovered in Icinga2 before v2.12.0-rc1. The prepare-dirs script (run as part of the icinga2
    systemd service) executes chmod 2750 /run/icinga2/cmd. /run/icinga2 is under control of an unprivileged
    user by default. If /run/icinga2/cmd is a symlink, then it will by followed and arbitrary files can be
    changed to mode 2750 by the unprivileged icinga2 user. (CVE-2020-14004)

  - Icinga 2 v2.8.0 through v2.11.7 and v2.12.2 has an issue where revoked certificates due for renewal will
    automatically be renewed, ignoring the CRL. This issue is fixed in Icinga 2 v2.11.8 and v2.12.3.
    (CVE-2020-29663)

  - Icinga is a monitoring system which checks the availability of network resources, notifies users of
    outages, and generates performance data for reporting. In versions 2.5.0 through 2.13.0,
    ElasticsearchWriter, GelfWriter, InfluxdbWriter and Influxdb2Writer do not verify the server's certificate
    despite a certificate authority being specified. Icinga 2 instances which connect to any of the mentioned
    time series databases (TSDBs) using TLS over a spoofable infrastructure should immediately upgrade to
    version 2.13.1, 2.12.6, or 2.11.11 to patch the issue. Such instances should also change the credentials
    (if any) used by the TSDB writer feature to authenticate against the TSDB. There are no workarounds aside
    from upgrading. (CVE-2021-37698)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1180147");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189653");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-October/012665.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4060c735");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14004");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29663");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37698");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-29663");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:icinga2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:icinga2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:icinga2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:icinga2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:icinga2-ido-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:icinga2-ido-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:icinga2-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim-icinga2");
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
if (os_ver == "SLES12" && (! preg(pattern:"^(0|2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP0/2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'icinga2-2.8.2-3.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-2.8.2-3.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-2.8.2-3.6.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-2.8.2-3.6.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-2.8.2-3.6.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-2.8.2-3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-2.8.2-3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-2.8.2-3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-2.8.2-3.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-2.8.2-3.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-bin-2.8.2-3.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-bin-2.8.2-3.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-bin-2.8.2-3.6.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-bin-2.8.2-3.6.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-bin-2.8.2-3.6.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-bin-2.8.2-3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-bin-2.8.2-3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-bin-2.8.2-3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-bin-2.8.2-3.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-bin-2.8.2-3.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-common-2.8.2-3.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-common-2.8.2-3.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-common-2.8.2-3.6.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-common-2.8.2-3.6.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-common-2.8.2-3.6.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-common-2.8.2-3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-common-2.8.2-3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-common-2.8.2-3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-common-2.8.2-3.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-common-2.8.2-3.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-doc-2.8.2-3.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-doc-2.8.2-3.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-doc-2.8.2-3.6.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-doc-2.8.2-3.6.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-doc-2.8.2-3.6.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-doc-2.8.2-3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-doc-2.8.2-3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-doc-2.8.2-3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-doc-2.8.2-3.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-doc-2.8.2-3.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-mysql-2.8.2-3.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-mysql-2.8.2-3.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-mysql-2.8.2-3.6.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-mysql-2.8.2-3.6.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-mysql-2.8.2-3.6.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-mysql-2.8.2-3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-mysql-2.8.2-3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-mysql-2.8.2-3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-mysql-2.8.2-3.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-mysql-2.8.2-3.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-pgsql-2.8.2-3.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-pgsql-2.8.2-3.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-pgsql-2.8.2-3.6.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-pgsql-2.8.2-3.6.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-pgsql-2.8.2-3.6.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-pgsql-2.8.2-3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-pgsql-2.8.2-3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-pgsql-2.8.2-3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-pgsql-2.8.2-3.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-ido-pgsql-2.8.2-3.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-libs-2.8.2-3.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-libs-2.8.2-3.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-libs-2.8.2-3.6.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-libs-2.8.2-3.6.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-libs-2.8.2-3.6.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-libs-2.8.2-3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-libs-2.8.2-3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-libs-2.8.2-3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-libs-2.8.2-3.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'icinga2-libs-2.8.2-3.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'vim-icinga2-2.8.2-3.6.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'vim-icinga2-2.8.2-3.6.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'vim-icinga2-2.8.2-3.6.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'vim-icinga2-2.8.2-3.6.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'vim-icinga2-2.8.2-3.6.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'vim-icinga2-2.8.2-3.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'vim-icinga2-2.8.2-3.6.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'vim-icinga2-2.8.2-3.6.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'vim-icinga2-2.8.2-3.6.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']},
    {'reference':'vim-icinga2-2.8.2-3.6.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.2', 'SLES_SAP-release-12.3', 'SLES_SAP-release-12.4', 'SLES_SAP-release-12.5', 'SLE_HPC-release-12.2', 'SLE_HPC-release-12.3', 'SLE_HPC-release-12.4', 'SLE_HPC-release-12.5', 'sle-module-hpc-release-12-0', 'sles-release-12.2', 'sles-release-12.3', 'sles-release-12.4', 'sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'icinga2 / icinga2-bin / icinga2-common / icinga2-doc / etc');
}
