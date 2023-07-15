##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2019:3390. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145624);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/23");

  script_cve_id("CVE-2018-15518", "CVE-2018-19870", "CVE-2018-19873");
  script_bugtraq_id(106286, 106327);
  script_xref(name:"RHSA", value:"2019:3390");

  script_name(english:"CentOS 8 : qt5-qtbase (CESA-2019:3390)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2019:3390 advisory.

  - qt5-qtbase: Double free in QXmlStreamReader (CVE-2018-15518)

  - qt5-qtbase: QImage allocation failure in qgifhandler (CVE-2018-19870)

  - qt5-qtbase: QBmpHandler segmentation fault on malformed BMP file (CVE-2018-19873)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3390");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19873");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-assistant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-doctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-linguist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qdbusviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qtbase-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-libs-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-libs-designercomponents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-libs-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt5-qttools-static");
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
include('misc_func.inc');
include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/CentOS/release');
if (isnull(release) || 'CentOS' >!< release) audit(AUDIT_OS_NOT, 'CentOS');
os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >< release) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS Stream ' + os_ver);
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'qt5-assistant-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-assistant-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-designer-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-designer-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-doctools-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-doctools-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-linguist-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-linguist-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qdbusviewer-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qdbusviewer-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-5.11.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-5.11.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-common-5.11.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-common-5.11.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-devel-5.11.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-devel-5.11.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-examples-5.11.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-examples-5.11.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-gui-5.11.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-gui-5.11.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-mysql-5.11.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-mysql-5.11.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-odbc-5.11.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-odbc-5.11.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-postgresql-5.11.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-postgresql-5.11.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-static-5.11.1-7.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qtbase-static-5.11.1-7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-common-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-common-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-devel-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-devel-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-examples-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-examples-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-designer-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-designer-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-designercomponents-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-designercomponents-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-help-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-libs-help-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-static-5.11.1-9.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qt5-qttools-static-5.11.1-9.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) release = 'CentOS-' + package_array['release'];
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qt5-assistant / qt5-designer / qt5-doctools / qt5-linguist / etc');
}
