#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5179-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155939);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-28831",
    "CVE-2021-42374",
    "CVE-2021-42378",
    "CVE-2021-42379",
    "CVE-2021-42380",
    "CVE-2021-42381",
    "CVE-2021-42382",
    "CVE-2021-42384",
    "CVE-2021-42385",
    "CVE-2021-42386"
  );
  script_xref(name:"USN", value:"5179-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 21.04 / 21.10 : BusyBox vulnerabilities (USN-5179-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 21.04 / 21.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-5179-1 advisory.

  - decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit on the huft_build result pointer,
    with a resultant invalid free or segmentation fault, via malformed gzip data. (CVE-2021-28831)

  - An out-of-bounds heap read in Busybox's unlzma applet leads to information leak and denial of service when
    crafted LZMA-compressed input is decompressed. This can be triggered by any applet/format that
    (CVE-2021-42374)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the getvar_i function (CVE-2021-42378)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the next_input_file function (CVE-2021-42379)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the clrvar function (CVE-2021-42380)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the hash_init function (CVE-2021-42381)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the getvar_s function (CVE-2021-42382)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the handle_special function (CVE-2021-42384)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the evaluate function (CVE-2021-42385)

  - A use-after-free in Busybox's awk applet leads to denial of service and possibly code execution when
    processing a crafted awk pattern in the nvalloc function (CVE-2021-42386)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5179-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42386");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:busybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:busybox-initramfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:busybox-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:busybox-syslogd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udhcpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:udhcpd");
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
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|21\.04|21\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 21.04 / 21.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


var pkgs = [
    {'osver': '18.04', 'pkgname': 'busybox', 'pkgver': '1:1.27.2-2ubuntu3.4'},
    {'osver': '18.04', 'pkgname': 'busybox-initramfs', 'pkgver': '1:1.27.2-2ubuntu3.4'},
    {'osver': '18.04', 'pkgname': 'busybox-static', 'pkgver': '1:1.27.2-2ubuntu3.4'},
    {'osver': '18.04', 'pkgname': 'busybox-syslogd', 'pkgver': '1:1.27.2-2ubuntu3.4'},
    {'osver': '18.04', 'pkgname': 'udhcpc', 'pkgver': '1:1.27.2-2ubuntu3.4'},
    {'osver': '18.04', 'pkgname': 'udhcpd', 'pkgver': '1:1.27.2-2ubuntu3.4'},
    {'osver': '20.04', 'pkgname': 'busybox', 'pkgver': '1:1.30.1-4ubuntu6.4'},
    {'osver': '20.04', 'pkgname': 'busybox-initramfs', 'pkgver': '1:1.30.1-4ubuntu6.4'},
    {'osver': '20.04', 'pkgname': 'busybox-static', 'pkgver': '1:1.30.1-4ubuntu6.4'},
    {'osver': '20.04', 'pkgname': 'busybox-syslogd', 'pkgver': '1:1.30.1-4ubuntu6.4'},
    {'osver': '20.04', 'pkgname': 'udhcpc', 'pkgver': '1:1.30.1-4ubuntu6.4'},
    {'osver': '20.04', 'pkgname': 'udhcpd', 'pkgver': '1:1.30.1-4ubuntu6.4'},
    {'osver': '21.04', 'pkgname': 'busybox', 'pkgver': '1:1.30.1-6ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'busybox-initramfs', 'pkgver': '1:1.30.1-6ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'busybox-static', 'pkgver': '1:1.30.1-6ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'busybox-syslogd', 'pkgver': '1:1.30.1-6ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'udhcpc', 'pkgver': '1:1.30.1-6ubuntu2.1'},
    {'osver': '21.04', 'pkgname': 'udhcpd', 'pkgver': '1:1.30.1-6ubuntu2.1'},
    {'osver': '21.10', 'pkgname': 'busybox', 'pkgver': '1:1.30.1-6ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'busybox-initramfs', 'pkgver': '1:1.30.1-6ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'busybox-static', 'pkgver': '1:1.30.1-6ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'busybox-syslogd', 'pkgver': '1:1.30.1-6ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'udhcpc', 'pkgver': '1:1.30.1-6ubuntu3.1'},
    {'osver': '21.10', 'pkgname': 'udhcpd', 'pkgver': '1:1.30.1-6ubuntu3.1'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'busybox / busybox-initramfs / busybox-static / busybox-syslogd / etc');
}
