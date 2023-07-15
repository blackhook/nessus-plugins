##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5011 and
# CentOS Errata and Security Advisory 2020:5011 respectively.
##

include('compat.inc');

if (description)
{
  script_id(143050);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/30");

  script_cve_id("CVE-2020-8622", "CVE-2020-8623", "CVE-2020-8624");
  script_xref(name:"RHSA", value:"2020:5011");

  script_name(english:"CentOS 7 : bind (CESA-2020:5011)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
CESA-2020:5011 advisory.

  - bind: truncated TSIG response can lead to an assertion failure (CVE-2020-8622)

  - bind: remotely triggerable assertion failure in pk11.c (CVE-2020-8623)

  - bind: incorrect enforcement of update-policy rules of type subdomain (CVE-2020-8624)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.centos.org/pipermail/centos-announce/2020-November/035850.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66bca8ef");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/400.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-export-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-libs-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-pkcs11-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-sdb-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bind-utils");
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
    {'reference':'bind-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-chroot-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-devel-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'bind-devel-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-export-devel-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'bind-export-devel-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-export-libs-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'bind-export-libs-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-libs-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'bind-libs-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-libs-lite-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'bind-libs-lite-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-license-9.11.4-26.P2.el7_9.2', 'sp':'9', 'release':'CentOS-7'},
    {'reference':'bind-lite-devel-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'bind-lite-devel-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-pkcs11-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-pkcs11-devel-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'bind-pkcs11-devel-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-pkcs11-libs-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'i686', 'release':'CentOS-7'},
    {'reference':'bind-pkcs11-libs-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-pkcs11-utils-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-sdb-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-sdb-chroot-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'},
    {'reference':'bind-utils-9.11.4-26.P2.el7_9.2', 'sp':'9', 'cpu':'x86_64', 'release':'CentOS-7'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind / bind-chroot / bind-devel / etc');
}
