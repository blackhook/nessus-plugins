#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:6781.
##

include('compat.inc');

if (description)
{
  script_id(167795);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-3080", "CVE-2022-38177", "CVE-2022-38178");
  script_xref(name:"RLSA", value:"2022:6781");

  script_name(english:"Rocky Linux 8 : bind9.16 (RLSA-2022:6781)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2022:6781 advisory.

  - By spoofing the target resolver with responses that have a malformed EdDSA signature, an attacker can
    trigger a small memory leak. It is possible to gradually erode available memory to the point where named
    crashes for lack of resources. (CVE-2022-38178)

  - By sending specific queries to the resolver, an attacker can cause named to crash. (CVE-2022-3080)

  - By spoofing the target resolver with responses that have a malformed ECDSA signature, an attacker can
    trigger a small memory leak. It is possible to gradually erode available memory to the point where named
    crashes for lack of resources. (CVE-2022-38177)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:6781");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-38178");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-dnssec-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-dnssec-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:bind9.16-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-bind9.16");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
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
    {'reference':'bind9.16-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-chroot-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-chroot-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-debuginfo-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-debuginfo-9.16.23-0.7.el8_6.1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-debuginfo-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-debugsource-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-debugsource-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-devel-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-devel-9.16.23-0.7.el8_6.1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-devel-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-dnssec-utils-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-dnssec-utils-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-dnssec-utils-debuginfo-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-dnssec-utils-debuginfo-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-doc-9.16.23-0.7.el8_6.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-libs-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-libs-9.16.23-0.7.el8_6.1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-libs-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-libs-debuginfo-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-libs-debuginfo-9.16.23-0.7.el8_6.1', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-libs-debuginfo-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-license-9.16.23-0.7.el8_6.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-utils-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-utils-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-utils-debuginfo-9.16.23-0.7.el8_6.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-utils-debuginfo-9.16.23-0.7.el8_6.1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'python3-bind9.16-9.16.23-0.7.el8_6.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9.16 / bind9.16-chroot / bind9.16-debuginfo / bind9.16-debugsource / etc');
}
