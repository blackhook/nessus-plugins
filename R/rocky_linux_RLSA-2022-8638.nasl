#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:8638.
##

include('compat.inc');

if (description)
{
  script_id(168480);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-42898");
  script_xref(name:"RLSA", value:"2022:8638");

  script_name(english:"Rocky Linux 8 : krb5 (RLSA-2022:8638)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
RLSA-2022:8638 advisory.

  - PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that
    may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit
    platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other
    platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has a similar bug.
    (CVE-2022-42898)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:8638");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42898");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-pkinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-server-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:krb5-workstation-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libkadm5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libkadm5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'krb5-debuginfo-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-debuginfo-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-debuginfo-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-debugsource-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-debugsource-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-debugsource-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-devel-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-devel-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-devel-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-devel-debuginfo-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-devel-debuginfo-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-devel-debuginfo-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-libs-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-libs-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-libs-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-libs-debuginfo-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-libs-debuginfo-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-libs-debuginfo-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-pkinit-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-pkinit-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-pkinit-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-pkinit-debuginfo-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-pkinit-debuginfo-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-pkinit-debuginfo-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-debuginfo-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-debuginfo-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-debuginfo-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-ldap-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-ldap-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-ldap-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-ldap-debuginfo-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-ldap-debuginfo-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-ldap-debuginfo-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-workstation-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-workstation-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-workstation-debuginfo-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-workstation-debuginfo-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5-debuginfo-1.18.2-22.el8_7', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5-debuginfo-1.18.2-22.el8_7', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5-debuginfo-1.18.2-22.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'krb5-debuginfo / krb5-debugsource / krb5-devel / krb5-devel-debuginfo / etc');
}
