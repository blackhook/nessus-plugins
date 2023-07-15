#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:0953.
##

include('compat.inc');

if (description)
{
  script_id(173993);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/19");

  script_cve_id("CVE-2022-45061");
  script_xref(name:"RLSA", value:"2023:0953");
  script_xref(name:"IAVA", value:"2022-A-0467-S");
  script_xref(name:"IAVA", value:"2023-A-0061-S");

  script_name(english:"Rocky Linux 9 : python3.9 (RLSA-2023:0953)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2023:0953 advisory.

  - An issue was discovered in Python before 3.11.1. An unnecessary quadratic algorithm exists in one path
    when processing some inputs to the IDNA (RFC 3490) decoder, such that a crafted, unreasonably long name
    being presented to the decoder could lead to a CPU denial of service. Hostnames are often supplied by
    remote servers that could be controlled by a malicious actor; in such a scenario, they could trigger
    excessive CPU consumption on the client attempting to make use of an attacker-supplied supposed hostname.
    For example, the attack payload could be placed in the Location header of an HTTP response with status
    code 302. A fix is planned in 3.11.1, 3.10.9, 3.9.16, 3.8.16, and 3.7.16. (CVE-2022-45061)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:0953");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2144072");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45061");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python-unversioned-command");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-tkinter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3.9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:9");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 9.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'python-unversioned-command-3.9.14-1.el9_1.2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-3.9.14-1.el9_1.2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-3.9.14-1.el9_1.2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-3.9.14-1.el9_1.2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-debug-3.9.14-1.el9_1.2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-debug-3.9.14-1.el9_1.2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-debug-3.9.14-1.el9_1.2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-devel-3.9.14-1.el9_1.2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-devel-3.9.14-1.el9_1.2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-devel-3.9.14-1.el9_1.2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-idle-3.9.14-1.el9_1.2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-idle-3.9.14-1.el9_1.2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-idle-3.9.14-1.el9_1.2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libs-3.9.14-1.el9_1.2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libs-3.9.14-1.el9_1.2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libs-3.9.14-1.el9_1.2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-test-3.9.14-1.el9_1.2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-test-3.9.14-1.el9_1.2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-test-3.9.14-1.el9_1.2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-tkinter-3.9.14-1.el9_1.2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-tkinter-3.9.14-1.el9_1.2', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-tkinter-3.9.14-1.el9_1.2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.9-debuginfo-3.9.14-1.el9_1.2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.9-debuginfo-3.9.14-1.el9_1.2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-unversioned-command / python3 / python3-debug / python3-devel / etc');
}
