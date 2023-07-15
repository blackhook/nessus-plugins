#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0036-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158130);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-15803", "CVE-2021-27927", "CVE-2022-23134");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/08");

  script_name(english:"openSUSE 15 Security Update : zabbix (openSUSE-SU-2022:0036-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0036-1 advisory.

  - Zabbix before 3.0.32rc1, 4.x before 4.0.22rc1, 4.1.x through 4.4.x before 4.4.10rc1, and 5.x before
    5.0.2rc1 allows stored XSS in the URL Widget. (CVE-2020-15803)

  - In Zabbix from 4.0.x before 4.0.28rc1, 5.0.0alpha1 before 5.0.10rc1, 5.2.x before 5.2.6rc1, and
    5.4.0alpha1 before 5.4.0beta2, the CControllerAuthenticationUpdate controller lacks a CSRF protection
    mechanism. The code inside this controller calls diableSIDValidation inside the init() method. An attacker
    doesn't have to know Zabbix user login credentials, but has to know the correct Zabbix URL and contact
    information of an existing user with sufficient privileges. (CVE-2021-27927)

  - After the initial setup process, some steps of setup.php file are reachable not only by super-
    administrators, but by unauthenticated users as well. Malicious actor can pass step checks and potentially
    change the configuration of Zabbix Frontend. (CVE-2022-23134)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1144018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183014");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194681");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EDFZEEJCPRPPDEWV6JULRJZVSQCMYOEY/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f2eadef");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15803");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-27927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-23134");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27927");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-java-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-phpfrontend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'zabbix-agent-4.0.37-lp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-java-gateway-4.0.37-lp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-phpfrontend-4.0.37-lp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-proxy-4.0.37-lp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-proxy-mysql-4.0.37-lp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-proxy-postgresql-4.0.37-lp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-proxy-sqlite-4.0.37-lp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-server-4.0.37-lp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-server-mysql-4.0.37-lp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'zabbix-server-postgresql-4.0.37-lp153.2.3.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'zabbix-agent / zabbix-java-gateway / zabbix-phpfrontend / zabbix-proxy / etc');
}
