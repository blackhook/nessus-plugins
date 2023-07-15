#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:8493.
##

include('compat.inc');

if (description)
{
  script_id(167845);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/06");

  script_cve_id("CVE-2022-42919");
  script_xref(name:"ALSA", value:"2022:8493");
  script_xref(name:"IAVA", value:"2022-A-0467-S");
  script_xref(name:"IAVA", value:"2023-A-0061-S");

  script_name(english:"AlmaLinux 9 : python3.9 (ALSA-2022:8493)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2022:8493 advisory.

  - Python 3.9.x and 3.10.x through 3.10.8 on Linux allows local privilege escalation in a non-default
    configuration. The Python multiprocessing library, when used with the forkserver start method on Linux,
    allows pickles to be deserialized from any user in the same machine local network namespace, which in many
    system configurations means any user on the same machine. Pickles can execute arbitrary code. Thus, this
    allows for local user privilege escalation to the user that any forkserver process is running as. Setting
    multiprocessing.util.abstract_sockets_supported to False is a workaround. The forkserver start method for
    multiprocessing is not the default start method. This issue is Linux specific because only Linux supports
    abstract namespace sockets. CPython before 3.9 does not make use of Linux abstract namespace sockets by
    default. Support for users manually specifying an abstract namespace socket was added as a bugfix in 3.7.8
    and 3.8.4, but users would need to make specific uncommon API calls in order to do that in CPython before
    3.9. (CVE-2022-42919)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2022-8493.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42919");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(269);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python-unversioned-command");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-idle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'python-unversioned-command-3.9.14-1.el9_1.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-3.9.14-1.el9_1.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-debug-3.9.14-1.el9_1.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-devel-3.9.14-1.el9_1.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-idle-3.9.14-1.el9_1.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libs-3.9.14-1.el9_1.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-test-3.9.14-1.el9_1.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-tkinter-3.9.14-1.el9_1.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
      severity   : SECURITY_WARNING,
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
