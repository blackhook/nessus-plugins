##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4704-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145464);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2017-6892",
    "CVE-2017-12562",
    "CVE-2017-14245",
    "CVE-2017-14246",
    "CVE-2017-14634",
    "CVE-2017-16942",
    "CVE-2018-13139",
    "CVE-2018-19432",
    "CVE-2018-19661",
    "CVE-2018-19662",
    "CVE-2018-19758",
    "CVE-2019-3832"
  );
  script_bugtraq_id(105996, 107572, 107580);
  script_xref(name:"USN", value:"4704-1");

  script_name(english:"Ubuntu 16.04 LTS : libsndfile vulnerabilities (USN-4704-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4704-1 advisory.

  - In libsndfile version 1.0.28, an error in the aiff_read_chanmap() function (aiff.c) can be exploited to
    cause an out-of-bounds read memory access via a specially crafted AIFF file. (CVE-2017-6892)

  - Heap-based Buffer Overflow in the psf_binheader_writef function in common.c in libsndfile through 1.0.28
    allows remote attackers to cause a denial of service (application crash) or possibly have unspecified
    other impact. (CVE-2017-12562)

  - An out of bounds read in the function d2alaw_array() in alaw.c of libsndfile 1.0.28 may lead to a remote
    DoS attack or information disclosure, related to mishandling of the NAN and INFINITY floating-point
    values. (CVE-2017-14245)

  - An out of bounds read in the function d2ulaw_array() in ulaw.c of libsndfile 1.0.28 may lead to a remote
    DoS attack or information disclosure, related to mishandling of the NAN and INFINITY floating-point
    values. (CVE-2017-14246)

  - In libsndfile 1.0.28, a divide-by-zero error exists in the function double64_init() in double64.c, which
    may lead to DoS when playing a crafted audio file. (CVE-2017-14634)

  - In libsndfile 1.0.25 (fixed in 1.0.26), a divide-by-zero error exists in the function
    wav_w64_read_fmt_chunk() in wav_w64.c, which may lead to DoS when playing a crafted audio file.
    (CVE-2017-16942)

  - A stack-based buffer overflow in psf_memset in common.c in libsndfile 1.0.28 allows remote attackers to
    cause a denial of service (application crash) or possibly have unspecified other impact via a crafted
    audio file. The vulnerability can be triggered by the executable sndfile-deinterleave. (CVE-2018-13139)

  - An issue was discovered in libsndfile 1.0.28. There is a NULL pointer dereference in the function
    sf_write_int in sndfile.c, which will lead to a denial of service. (CVE-2018-19432)

  - An issue was discovered in libsndfile 1.0.28. There is a buffer over-read in the function i2ulaw_array in
    ulaw.c that will lead to a denial of service. (CVE-2018-19661)

  - An issue was discovered in libsndfile 1.0.28. There is a buffer over-read in the function i2alaw_array in
    alaw.c that will lead to a denial of service. (CVE-2018-19662)

  - There is a heap-based buffer over-read at wav.c in wav_write_header in libsndfile 1.0.28 that will cause a
    denial of service. (CVE-2018-19758)

  - It was discovered the fix for CVE-2018-19758 (libsndfile) was not complete and still allows a read beyond
    the limits of a buffer in wav_write_header() function in wav.c. A local attacker may use this flaw to make
    the application crash. (CVE-2019-3832)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4704-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libsndfile1, libsndfile1-dev and / or sndfile-programs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsndfile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsndfile1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sndfile-programs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'libsndfile1', 'pkgver': '1.0.25-10ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'libsndfile1-dev', 'pkgver': '1.0.25-10ubuntu0.16.04.3'},
    {'osver': '16.04', 'pkgname': 'sndfile-programs', 'pkgver': '1.0.25-10ubuntu0.16.04.3'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libsndfile1 / libsndfile1-dev / sndfile-programs');
}