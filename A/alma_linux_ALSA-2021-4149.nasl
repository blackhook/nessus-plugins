#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:4149.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157623);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/14");

  script_cve_id(
    "CVE-2020-35653",
    "CVE-2020-35655",
    "CVE-2021-25287",
    "CVE-2021-25288",
    "CVE-2021-25290",
    "CVE-2021-25292",
    "CVE-2021-25293",
    "CVE-2021-27921",
    "CVE-2021-27922",
    "CVE-2021-27923",
    "CVE-2021-28675",
    "CVE-2021-28676",
    "CVE-2021-28677",
    "CVE-2021-28678",
    "CVE-2021-34552"
  );
  script_xref(name:"ALSA", value:"2021:4149");

  script_name(english:"AlmaLinux 8 : python-pillow (ALSA-2021:4149)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ALSA-2021:4149 advisory.

  - In Pillow before 8.1.0, PcxDecode has a buffer over-read when decoding a crafted PCX file because the
    user-supplied stride value is trusted for buffer calculations. (CVE-2020-35653)

  - In Pillow before 8.1.0, SGIRleDecode has a 4-byte buffer over-read when decoding crafted SGI RLE image
    files because offsets and length tables are mishandled. (CVE-2020-35655)

  - An issue was discovered in Pillow before 8.2.0. There is an out-of-bounds read in J2kDecode, in
    j2ku_graya_la. (CVE-2021-25287)

  - An issue was discovered in Pillow before 8.2.0. There is an out-of-bounds read in J2kDecode, in
    j2ku_gray_i. (CVE-2021-25288)

  - An issue was discovered in Pillow before 8.1.1. In TiffDecode.c, there is a negative-offset memcpy with an
    invalid size. (CVE-2021-25290)

  - An issue was discovered in Pillow before 8.1.1. The PDF parser allows a regular expression DoS (ReDoS)
    attack via a crafted PDF file because of a catastrophic backtracking regex. (CVE-2021-25292)

  - An issue was discovered in Pillow before 8.1.1. There is an out-of-bounds read in SGIRleDecode.c.
    (CVE-2021-25293)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for a BLP container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27921)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for an ICNS container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27922)

  - Pillow before 8.1.1 allows attackers to cause a denial of service (memory consumption) because the
    reported size of a contained image is not properly checked for an ICO container, and thus an attempted
    memory allocation can be very large. (CVE-2021-27923)

  - An issue was discovered in Pillow before 8.2.0. PSDImagePlugin.PsdImageFile lacked a sanity check on the
    number of input layers relative to the size of the data block. This could lead to a DoS on Image.open
    prior to Image.load. (CVE-2021-28675)

  - An issue was discovered in Pillow before 8.2.0. For FLI data, FliDecode did not properly check that the
    block advance was non-zero, potentially leading to an infinite loop on load. (CVE-2021-28676)

  - An issue was discovered in Pillow before 8.2.0. For EPS data, the readline implementation used in
    EPSImageFile has to deal with any combination of \r and \n as line endings. It used an accidentally
    quadratic method of accumulating lines while looking for a line ending. A malicious EPS file could use
    this to perform a DoS of Pillow in the open phase, before an image was accepted for opening.
    (CVE-2021-28677)

  - An issue was discovered in Pillow before 8.2.0. For BLP data, BlpImagePlugin did not properly check that
    reads (after jumping to file offsets) returned data. This could lead to a DoS where the decoder could be
    run a large number of times on empty data. (CVE-2021-28678)

  - Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass
    controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.
    (CVE-2021-34552)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-4149.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected python3-pillow package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34552");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-pillow");
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
    {'reference':'python3-pillow-5.1.1-16.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3-pillow');
}
