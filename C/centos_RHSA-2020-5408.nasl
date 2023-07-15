##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5408 and
# CentOS Errata and Security Advisory 2020:5408 respectively.
##

include('compat.inc');

if (description)
{
  script_id(146881);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/01");

  script_cve_id("CVE-2020-14347", "CVE-2020-14360", "CVE-2020-25712");
  script_xref(name:"RHSA", value:"2020:5408");

  script_name(english:"CentOS 7 : xorg-x11-server (CESA-2020:5408)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:5408 advisory.

  - xorg-x11-server: Leak of uninitialized heap memory from the X server to clients in AllocatePixmap of
    dix/pixmap.c (CVE-2020-14347)

  - xorg-x11-server: Out-of-bounds access in XkbSetMap function (CVE-2020-14360)

  - xorg-x11-server: XkbSetDeviceInfo heap-based buffer overflow privilege escalation vulnerability
    (CVE-2020-25712)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-announce/2021-February/048276.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a946e15");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/119.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/122.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/665.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14360");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119, 122, 665);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xwayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'xorg-x11-server-common-1.20.4-15.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.4-15.el7_9', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-devel-1.20.4-15.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-source-1.20.4-15.el7_9', 'sp':'9', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xdmx-1.20.4-15.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xephyr-1.20.4-15.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xnest-1.20.4-15.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xorg-1.20.4-15.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xvfb-1.20.4-15.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'xorg-x11-server-Xwayland-1.20.4-15.el7_9', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / xorg-x11-server-Xnest / etc');
}
