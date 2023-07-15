##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3978 and
# CentOS Errata and Security Advisory 2020:3978 respectively.
##

include('compat.inc');

if (description)
{
  script_id(141596);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2019-12450", "CVE-2019-14822");
  script_xref(name:"RHSA", value:"2020:3978");

  script_name(english:"CentOS 7 : glib2 and ibus (CESA-2020:3978)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:3978 advisory.

  - glib2: file_copy_fallback in gio/gfile.c in GNOME GLib does not properly restrict file permissions while a
    copy operation is in progress (CVE-2019-12450)

  - ibus: missing authorization allows local attacker to access the input bus of another user (CVE-2019-14822)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-October/012712.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d20f20b");
  # https://lists.centos.org/pipermail/centos-cr-announce/2020-October/012731.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e6a86b2");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/552.html");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/862.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12450");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(552, 862);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glib2-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibus-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibus-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibus-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibus-pygtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ibus-setup");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'CentOS 7.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'glib2-2.56.1-7.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'glib2-2.56.1-7.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'glib2-devel-2.56.1-7.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'glib2-devel-2.56.1-7.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'glib2-doc-2.56.1-7.el7', 'release':'CentOS-7'},
    {'reference':'glib2-fam-2.56.1-7.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'glib2-static-2.56.1-7.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'glib2-static-2.56.1-7.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'glib2-tests-2.56.1-7.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'ibus-1.5.17-11.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'ibus-1.5.17-11.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'ibus-devel-1.5.17-11.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'ibus-devel-1.5.17-11.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'ibus-devel-docs-1.5.17-11.el7', 'release':'CentOS-7'},
    {'reference':'ibus-gtk2-1.5.17-11.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'ibus-gtk2-1.5.17-11.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'ibus-gtk3-1.5.17-11.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'ibus-gtk3-1.5.17-11.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'ibus-libs-1.5.17-11.el7', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'ibus-libs-1.5.17-11.el7', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'ibus-pygtk2-1.5.17-11.el7', 'release':'CentOS-7'},
    {'reference':'ibus-setup-1.5.17-11.el7', 'release':'CentOS-7'}
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
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +
    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glib2 / glib2-devel / glib2-doc / etc');
}
