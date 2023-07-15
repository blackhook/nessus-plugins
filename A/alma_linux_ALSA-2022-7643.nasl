#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2022:7643.
##

include('compat.inc');

if (description)
{
  script_id(167314);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/29");

  script_cve_id("CVE-2021-25220", "CVE-2022-0396");
  script_xref(name:"ALSA", value:"2022:7643");

  script_name(english:"AlmaLinux 8 : bind9.16 (ALSA-2022:7643)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2022:7643 advisory.

  - BIND 9.11.0 -> 9.11.36 9.12.0 -> 9.16.26 9.17.0 -> 9.18.0 BIND Supported Preview Editions: 9.11.4-S1 ->
    9.11.36-S1 9.16.8-S1 -> 9.16.26-S1 Versions of BIND 9 earlier than those shown - back to 9.1.0, including
    Supported Preview Editions - are also believed to be affected but have not been tested as they are EOL.
    The cache could become poisoned with incorrect records leading to queries being made to the wrong servers,
    which might also result in false information being returned to clients. (CVE-2021-25220)

  - BIND 9.16.11 -> 9.16.26, 9.17.0 -> 9.18.0 and versions 9.16.11-S1 -> 9.16.26-S1 of the BIND Supported
    Preview Edition. Specifically crafted TCP streams can cause connections to BIND to remain in CLOSE_WAIT
    status for an indefinite period of time, even after the client has terminated the connection.
    (CVE-2022-0396)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2022-7643.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(404, 444, 459);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind9.16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind9.16-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind9.16-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind9.16-dnssec-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind9.16-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind9.16-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind9.16-license");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:bind9.16-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-bind9.16");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'bind9.16-9.16.23-0.9.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-chroot-9.16.23-0.9.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-devel-9.16.23-0.9.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-dnssec-utils-9.16.23-0.9.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-doc-9.16.23-0.9.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-libs-9.16.23-0.9.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-license-9.16.23-0.9.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'bind9.16-utils-9.16.23-0.9.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'},
    {'reference':'python3-bind9.16-9.16.23-0.9.el8.1', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'32'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'bind9.16 / bind9.16-chroot / bind9.16-devel / bind9.16-dnssec-utils / etc');
}
