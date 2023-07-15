#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:1804.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157526);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2020-14344",
    "CVE-2020-14345",
    "CVE-2020-14346",
    "CVE-2020-14347",
    "CVE-2020-14360",
    "CVE-2020-14361",
    "CVE-2020-14362",
    "CVE-2020-14363",
    "CVE-2020-25712"
  );
  script_xref(name:"ALSA", value:"2021:1804");
  script_xref(name:"IAVB", value:"2020-B-0051");

  script_name(english:"AlmaLinux 8 : userspace graphics, xorg-x11, and mesa (ALSA-2021:1804)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2021:1804 advisory.

  - An integer overflow leading to a heap-buffer overflow was found in The X Input Method (XIM) client was
    implemented in libX11 before version 1.6.10. As per upstream this is security relevant when setuid
    programs call XIM client functions while running with elevated privileges. No such programs are shipped
    with Red Hat Enterprise Linux. (CVE-2020-14344)

  - A flaw was found in X.Org Server before xorg-x11-server 1.20.9. An Out-Of-Bounds access in XkbSetNames
    function may lead to a privilege escalation vulnerability. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system availability. (CVE-2020-14345)

  - A flaw was found in xorg-x11-server before 1.20.9. An integer underflow in the X input extension protocol
    decoding in the X server may lead to arbitrary access of memory contents. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-14346)

  - A flaw was found in the way xserver memory was not properly initialized. This could leak parts of server
    memory to the X client. In cases where Xorg server runs with elevated privileges, this could result in
    possible ASLR bypass. Xorg-server before version 1.20.9 is vulnerable. (CVE-2020-14347)

  - A flaw was found in the X.Org Server before version 1.20.10. An out-of-bounds access in the XkbSetMap
    function may lead to a privilege escalation vulnerability. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as system availability. (CVE-2020-14360)

  - A flaw was found in X.Org Server before xorg-x11-server 1.20.9. An Integer underflow leading to heap-
    buffer overflow may lead to a privilege escalation vulnerability. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-14361,
    CVE-2020-14362)

  - An integer overflow vulnerability leading to a double-free was found in libX11. This flaw allows a local
    privileged attacker to cause an application compiled with libX11 to crash, or in some cases, result in
    arbitrary code execution. The highest threat from this flaw is to confidentiality, integrity as well as
    system availability. (CVE-2020-14363)

  - A flaw was found in xorg-x11-server before 1.20.10. A heap-buffer overflow in XkbSetDeviceInfo may lead to
    a privilege escalation vulnerability. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25712)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-1804.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libglvnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libglvnd-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libglvnd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libglvnd-egl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libglvnd-gles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libglvnd-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libglvnd-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libinput-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libwacom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mesa-libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:mesa-libgbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:xorg-x11-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'libglvnd-1.3.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-core-devel-1.3.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-core-devel-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-devel-1.3.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-devel-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-egl-1.3.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-egl-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-gles-1.3.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-gles-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-glx-1.3.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-glx-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-opengl-1.3.2-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libglvnd-opengl-1.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libinput-devel-1.16.3-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libinput-devel-1.16.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-devel-1.6-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwacom-devel-1.6-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-devel-20.3.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libgbm-devel-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-devel-20.3.3-2.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'mesa-libOSMesa-devel-20.3.3-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-drivers-7.7-30.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.10-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.10-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-source-1.20.10-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libglvnd / libglvnd-core-devel / libglvnd-devel / libglvnd-egl / etc');
}
