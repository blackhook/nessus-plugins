##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5555-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163923);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2022-1920",
    "CVE-2022-1921",
    "CVE-2022-1922",
    "CVE-2022-1923",
    "CVE-2022-1924",
    "CVE-2022-1925",
    "CVE-2022-2122"
  );
  script_xref(name:"USN", value:"5555-1");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS : GStreamer Good Plugins vulnerabilities (USN-5555-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5555-1 advisory.

  - Integer overflow in matroskademux element in gst_matroska_demux_add_wvpk_header function which allows a
    heap overwrite while parsing matroska files. Potential for arbitrary code execution through heap
    overwrite. (CVE-2022-1920)

  - Integer overflow in avidemux element in gst_avi_demux_invert function which allows a heap overwrite while
    parsing avi files. Potential for arbitrary code execution through heap overwrite. (CVE-2022-1921)

  - DOS / potential heap overwrite in mkv demuxing using zlib decompression. Integer overflow in matroskademux
    element in gst_matroska_decompress_data function which causes a segfault, or could cause a heap overwrite,
    depending on libc and OS. Depending on the libc used, and the underlying OS capabilities, it could be just
    a segfault or a heap overwrite. If the libc uses mmap for large chunks, and the OS supports mmap, then it
    is just a segfault (because the realloc before the integer overflow will use mremap to reduce the size of
    the chunk, and it will start to write to unmapped memory). However, if using a libc implementation that
    does not use mmap, or if the OS does not support mmap while using libc, then this could result in a heap
    overwrite. (CVE-2022-1922)

  - DOS / potential heap overwrite in mkv demuxing using bzip decompression. Integer overflow in matroskademux
    element in bzip decompression function which causes a segfault, or could cause a heap overwrite, depending
    on libc and OS. Depending on the libc used, and the underlying OS capabilities, it could be just a
    segfault or a heap overwrite. If the libc uses mmap for large chunks, and the OS supports mmap, then it is
    just a segfault (because the realloc before the integer overflow will use mremap to reduce the size of the
    chunk, and it will start to write to unmapped memory). However, if using a libc implementation that does
    not use mmap, or if the OS does not support mmap while using libc, then this could result in a heap
    overwrite. (CVE-2022-1923)

  - DOS / potential heap overwrite in mkv demuxing using lzo decompression. Integer overflow in matroskademux
    element in lzo decompression function which causes a segfault, or could cause a heap overwrite, depending
    on libc and OS. Depending on the libc used, and the underlying OS capabilities, it could be just a
    segfault or a heap overwrite. If the libc uses mmap for large chunks, and the OS supports mmap, then it is
    just a segfault (because the realloc before the integer overflow will use mremap to reduce the size of the
    chunk, and it will start to write to unmapped memory). However, if using a libc implementation that does
    not use mmap, or if the OS does not support mmap while using libc, then this could result in a heap
    overwrite. (CVE-2022-1924)

  - DOS / potential heap overwrite in mkv demuxing using HEADERSTRIP decompression. Integer overflow in
    matroskaparse element in gst_matroska_decompress_data function which causes a heap overflow. Due to
    restrictions on chunk sizes in the matroskademux element, the overflow can't be triggered, however the
    matroskaparse element has no size checks. (CVE-2022-1925)

  - DOS / potential heap overwrite in qtdemux using zlib decompression. Integer overflow in qtdemux element in
    qtdemux_inflate function which causes a segfault, or could cause a heap overwrite, depending on libc and
    OS. Depending on the libc used, and the underlying OS capabilities, it could be just a segfault or a heap
    overwrite. (CVE-2022-2122)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5555-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2122");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gstreamer1.0-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-plugins-good1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libgstreamer-plugins-good1.0-dev");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release || '20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'gstreamer1.0-plugins-good', 'pkgver': '1.8.3-1ubuntu0.5+esm1'},
    {'osver': '16.04', 'pkgname': 'gstreamer1.0-pulseaudio', 'pkgver': '1.8.3-1ubuntu0.5+esm1'},
    {'osver': '16.04', 'pkgname': 'libgstreamer-plugins-good1.0-0', 'pkgver': '1.8.3-1ubuntu0.5+esm1'},
    {'osver': '16.04', 'pkgname': 'libgstreamer-plugins-good1.0-dev', 'pkgver': '1.8.3-1ubuntu0.5+esm1'},
    {'osver': '18.04', 'pkgname': 'gstreamer1.0-gtk3', 'pkgver': '1.14.5-0ubuntu1~18.04.3'},
    {'osver': '18.04', 'pkgname': 'gstreamer1.0-plugins-good', 'pkgver': '1.14.5-0ubuntu1~18.04.3'},
    {'osver': '18.04', 'pkgname': 'gstreamer1.0-pulseaudio', 'pkgver': '1.14.5-0ubuntu1~18.04.3'},
    {'osver': '18.04', 'pkgname': 'gstreamer1.0-qt5', 'pkgver': '1.14.5-0ubuntu1~18.04.3'},
    {'osver': '18.04', 'pkgname': 'libgstreamer-plugins-good1.0-0', 'pkgver': '1.14.5-0ubuntu1~18.04.3'},
    {'osver': '18.04', 'pkgname': 'libgstreamer-plugins-good1.0-dev', 'pkgver': '1.14.5-0ubuntu1~18.04.3'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-gtk3', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-plugins-good', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-pulseaudio', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'gstreamer1.0-qt5', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libgstreamer-plugins-good1.0-0', 'pkgver': '1.16.3-0ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libgstreamer-plugins-good1.0-dev', 'pkgver': '1.16.3-0ubuntu1.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gstreamer1.0-gtk3 / gstreamer1.0-plugins-good / etc');
}
