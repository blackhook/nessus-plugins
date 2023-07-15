#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2021:1620. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149764);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/02");

  script_cve_id("CVE-2020-12362");
  script_xref(name:"RHSA", value:"2021:1620");

  script_name(english:"CentOS 8 : linux-firmware (CESA-2021:1620)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2021:1620 advisory.

  - kernel: Integer overflow in Intel(R) Graphics Drivers (CVE-2020-12362)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2021:1620");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12362");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libertas-sd8686-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libertas-sd8787-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libertas-usb8388-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libertas-usb8388-olpc-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:linux-firmware");
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
if ('CentOS Stream' >!< release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

pkgs = [
    {'reference':'iwl100-firmware-39.31.5.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl1000-firmware-39.31.5.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'iwl105-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl135-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl2000-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl2030-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl3160-firmware-25.30.13.0-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'iwl3945-firmware-15.32.2.9-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl4965-firmware-228.61.2.24-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl5000-firmware-8.83.5.1_1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl5150-firmware-8.24.2.2-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6000-firmware-9.221.4.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6000g2a-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6000g2b-firmware-18.168.6.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl6050-firmware-41.28.5.1-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'iwl7260-firmware-25.30.13.0-102.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'libertas-sd8686-firmware-20201218-102.git05789708.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libertas-sd8787-firmware-20201218-102.git05789708.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libertas-usb8388-firmware-20201218-102.git05789708.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libertas-usb8388-olpc-firmware-20201218-102.git05789708.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'linux-firmware-20201218-102.git05789708.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'iwl100-firmware / iwl1000-firmware / iwl105-firmware / iwl135-firmware / etc');
}
