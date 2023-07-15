#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0040-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(171001);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/05");

  script_cve_id("CVE-2022-38725");

  script_name(english:"openSUSE 15 Security Update : syslog-ng (openSUSE-SU-2023:0040-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2023:0040-1 advisory.

  - An integer overflow in the RFC3164 parser in One Identity syslog-ng 3.0 through 3.37 allows remote
    attackers to cause a Denial of Service via crafted syslog input that is mishandled by the tcp or network
    function. syslog-ng Premium Edition 7.0.30 and syslog-ng Store Box 6.10.0 are also affected.
    (CVE-2022-38725)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207460");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KPVYCA5YR6CSNRS7QCCRAUZAWCZP53WG/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9730b765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-38725");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38725");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libevtlog-3_35-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng-geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng-mqtt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng-smtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:syslog-ng-sql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'libevtlog-3_35-0-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-curl-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-devel-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-geoip-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-java-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-mqtt-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-python-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-redis-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-smtp-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-snmp-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'syslog-ng-sql-3.35.1-bp154.3.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libevtlog-3_35-0 / syslog-ng / syslog-ng-curl / syslog-ng-devel / etc');
}
