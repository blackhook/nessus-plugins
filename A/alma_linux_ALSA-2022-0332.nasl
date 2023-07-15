#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:0332.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158825);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/03");

  script_cve_id("CVE-2021-44142");
  script_xref(name:"ALSA", value:"2022:0332");
  script_xref(name:"IAVA", value:"2022-A-0054-S");

  script_name(english:"AlmaLinux 8 : samba (ALSA-2022:0332)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2022:0332 advisory.

  - The Samba vfs_fruit module uses extended file attributes (EA, xattr) to provide ...enhanced compatibility
    with Apple SMB clients and interoperability with a Netatalk 3 AFP fileserver. Samba versions prior to
    4.13.17, 4.14.12 and 4.15.5 with vfs_fruit configured allow out-of-bounds heap read and write via
    specially crafted extended file attributes. A remote attacker with write access to extended file
    attributes can execute arbitrary code with the privileges of smbd, typically root. (CVE-2021-44142)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-0332.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44142");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-client-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-common-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-common-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-krb5-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-test-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-vfs-iouring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:samba-winexe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'ctdb-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-4.14.5-9.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmbclient-devel-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-4.14.5-9.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libwbclient-devel-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-4.14.5-9.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-samba-test-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.14.5-9.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-client-libs-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-4.14.5-9.el8_5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-libs-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-common-tools-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-devel-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-krb5-printing-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.14.5-9.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-libs-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-pidl-4.14.5-9.el8_5', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-test-libs-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-vfs-iouring-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-clients-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-krb5-locator-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-4.14.5-9.el8_5', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winbind-modules-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'samba-winexe-4.14.5-9.el8_5', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ctdb / libsmbclient / libsmbclient-devel / libwbclient / etc');
}
