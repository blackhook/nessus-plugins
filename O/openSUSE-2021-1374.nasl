#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1374-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154211);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/19");

  script_cve_id("CVE-2021-33574", "CVE-2021-35942");

  script_name(english:"openSUSE 15 Security Update : glibc (openSUSE-SU-2021:1374-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1374-1 advisory.

  - The mq_notify function in the GNU C Library (aka glibc) versions 2.32 and 2.33 has a use-after-free. It
    may use the notification thread attributes object (passed through its struct sigevent parameter) after it
    has been freed by the caller, leading to a denial of service (application crash) or possibly unspecified
    other impact. (CVE-2021-33574)

  - The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in
    parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in
    a denial of service or disclosure of information. This occurs because atoi was used but strtoul should
    have been used to ensure correct calculations. (CVE-2021-35942)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187911");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YZGEXWUJCYCGR3DHTHHZAJYSGQP2SHMN/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8ea37af");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33574");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-35942");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33574");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'glibc-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-32bit-2.26-lp152.26.9.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-devel-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-devel-32bit-2.26-lp152.26.9.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-devel-static-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-devel-static-32bit-2.26-lp152.26.9.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-extra-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-html-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-i18ndata-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-info-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-locale-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-locale-base-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-locale-base-32bit-2.26-lp152.26.9.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-profile-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-profile-32bit-2.26-lp152.26.9.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-utils-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-utils-32bit-2.26-lp152.26.9.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nscd-2.26-lp152.26.9.1', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc / glibc-32bit / glibc-devel / glibc-devel-32bit / etc');
}
