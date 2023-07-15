#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:1849.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157588);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2020-4030",
    "CVE-2020-4033",
    "CVE-2020-11095",
    "CVE-2020-11096",
    "CVE-2020-11097",
    "CVE-2020-11098",
    "CVE-2020-11099",
    "CVE-2020-15103"
  );
  script_xref(name:"ALSA", value:"2021:1849");

  script_name(english:"AlmaLinux 8 : freerdp (ALSA-2021:1849)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ALSA-2021:1849 advisory.

  - In FreeRDP before version 2.1.2, there is an out of bounds read in TrioParse. Logging might bypass string
    length checks due to an integer overflow. This is fixed in version 2.1.2. (CVE-2020-4030)

  - In FreeRDP before version 2.1.2, there is an out of bounds read in RLEDECOMPRESS. All FreeRDP based
    clients with sessions with color depth < 32 are affected. This is fixed in version 2.1.2. (CVE-2020-4033)

  - In FreeRDP before version 2.1.2, an out of bound reads occurs resulting in accessing a memory location
    that is outside of the boundaries of the static array PRIMARY_DRAWING_ORDER_FIELD_BYTES. This is fixed in
    version 2.1.2. (CVE-2020-11095)

  - In FreeRDP before version 2.1.2, there is a global OOB read in update_read_cache_bitmap_v3_order. As a
    workaround, one can disable bitmap cache with -bitmap-cache (default). This is fixed in version 2.1.2.
    (CVE-2020-11096)

  - In FreeRDP before version 2.1.2, an out of bounds read occurs resulting in accessing a memory location
    that is outside of the boundaries of the static array PRIMARY_DRAWING_ORDER_FIELD_BYTES. This is fixed in
    version 2.1.2. (CVE-2020-11097)

  - In FreeRDP before version 2.1.2, there is an out-of-bound read in glyph_cache_put. This affects all
    FreeRDP clients with `+glyph-cache` option enabled This is fixed in version 2.1.2. (CVE-2020-11098)

  - In FreeRDP before version 2.1.2, there is an out of bounds read in
    license_read_new_or_upgrade_license_packet. A manipulated license packet can lead to out of bound reads to
    an internal buffer. This is fixed in version 2.1.2. (CVE-2020-11099)

  - In FreeRDP less than or equal to 2.1.2, an integer overflow exists due to missing input sanitation in
    rdpegfx channel. All FreeRDP clients are affected. The input rectangles from the server are not checked
    against local surface coordinates and blindly accepted. A malicious server can send data that will crash
    the client later on (invalid length arguments to a `memcpy`) This has been fixed in 2.2.0. As a
    workaround, stop using command line arguments /gfx, /gfx-h264 and /network:auto (CVE-2020-15103)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-1849.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected freerdp-devel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-4033");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
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
    {'reference':'freerdp-devel-2.2.0-1.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'freerdp-devel-2.2.0-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp-devel');
}
