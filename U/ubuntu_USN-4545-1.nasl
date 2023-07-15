#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4545-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140800);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2017-9122",
    "CVE-2017-9123",
    "CVE-2017-9124",
    "CVE-2017-9125",
    "CVE-2017-9126",
    "CVE-2017-9127",
    "CVE-2017-9128"
  );
  script_xref(name:"USN", value:"4545-1");

  script_name(english:"Ubuntu 16.04 LTS : libquicktime vulnerabilities (USN-4545-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4545-1 advisory.

  - The quicktime_read_moov function in moov.c in libquicktime 1.2.4 allows remote attackers to cause a denial
    of service (infinite loop and CPU consumption) via a crafted mp4 file. (CVE-2017-9122)

  - The lqt_frame_duration function in lqt_quicktime.c in libquicktime 1.2.4 allows remote attackers to cause
    a denial of service (invalid memory read and application crash) via a crafted mp4 file. (CVE-2017-9123)

  - The quicktime_match_32 function in util.c in libquicktime 1.2.4 allows remote attackers to cause a denial
    of service (NULL pointer dereference and application crash) via a crafted mp4 file. (CVE-2017-9124)

  - The lqt_frame_duration function in lqt_quicktime.c in libquicktime 1.2.4 allows remote attackers to cause
    a denial of service (heap-based buffer over-read) via a crafted mp4 file. (CVE-2017-9125)

  - The quicktime_read_dref_table function in dref.c in libquicktime 1.2.4 allows remote attackers to cause a
    denial of service (heap-based buffer overflow and application crash) via a crafted mp4 file.
    (CVE-2017-9126)

  - The quicktime_user_atoms_read_atom function in useratoms.c in libquicktime 1.2.4 allows remote attackers
    to cause a denial of service (heap-based buffer overflow and application crash) via a crafted mp4 file.
    (CVE-2017-9127)

  - The quicktime_video_width function in lqt_quicktime.c in libquicktime 1.2.4 allows remote attackers to
    cause a denial of service (heap-based buffer over-read and application crash) via a crafted mp4 file.
    (CVE-2017-9128)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4545-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9122");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libquicktime-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libquicktime2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:quicktime-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:quicktime-x11utils");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'osver': '16.04', 'pkgname': 'libquicktime-dev', 'pkgver': '2:1.2.4-7+deb8u1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'libquicktime2', 'pkgver': '2:1.2.4-7+deb8u1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'quicktime-utils', 'pkgver': '2:1.2.4-7+deb8u1ubuntu0.1'},
    {'osver': '16.04', 'pkgname': 'quicktime-x11utils', 'pkgver': '2:1.2.4-7+deb8u1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libquicktime-dev / libquicktime2 / quicktime-utils / etc');
}