##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4382-2. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143270);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-11042",
    "CVE-2020-11045",
    "CVE-2020-11046",
    "CVE-2020-11048",
    "CVE-2020-11058",
    "CVE-2020-11521",
    "CVE-2020-11522",
    "CVE-2020-11523",
    "CVE-2020-11525",
    "CVE-2020-11526",
    "CVE-2020-13396",
    "CVE-2020-13397",
    "CVE-2020-13398"
  );
  script_xref(name:"USN", value:"4382-2");

  script_name(english:"Ubuntu 18.04 LTS : FreeRDP vulnerabilities (USN-4382-2)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4382-2 advisory.

  - In FreeRDP greater than 1.1 and before 2.0.0, there is an out-of-bounds read in update_read_icon_info. It
    allows reading a attacker-defined amount of client memory (32bit unsigned -> 4GB) to an intermediate
    buffer. This can be used to crash the client or store information for later retrieval. This has been
    patched in 2.0.0. (CVE-2020-11042)

  - In FreeRDP after 1.0 and before 2.0.0, there is an out-of-bound read in in update_read_bitmap_data that
    allows client memory to be read to an image buffer. The result displayed on screen as colour.
    (CVE-2020-11045)

  - In FreeRDP after 1.0 and before 2.0.0, there is a stream out-of-bounds seek in update_read_synchronize
    that could lead to a later out-of-bounds read. (CVE-2020-11046)

  - In FreeRDP after 1.0 and before 2.0.0, there is an out-of-bounds read. It only allows to abort a session.
    No data extraction is possible. This has been fixed in 2.0.0. (CVE-2020-11048)

  - In FreeRDP after 1.1 and before 2.0.0, a stream out-of-bounds seek in rdp_read_font_capability_set could
    lead to a later out-of-bounds read. As a result, a manipulated client or server might force a disconnect
    due to an invalid data read. This has been fixed in 2.0.0. (CVE-2020-11058)

  - libfreerdp/codec/planar.c in FreeRDP version > 1.0 through 2.0.0-rc4 has an Out-of-bounds Write.
    (CVE-2020-11521)

  - libfreerdp/gdi/gdi.c in FreeRDP > 1.0 through 2.0.0-rc4 has an Out-of-bounds Read. (CVE-2020-11522)

  - libfreerdp/gdi/region.c in FreeRDP versions > 1.0 through 2.0.0-rc4 has an Integer Overflow.
    (CVE-2020-11523)

  - libfreerdp/cache/bitmap.c in FreeRDP versions > 1.0 through 2.0.0-rc4 has an Out of bounds read.
    (CVE-2020-11525)

  - libfreerdp/core/update.c in FreeRDP versions > 1.1 through 2.0.0-rc4 has an Out-of-bounds Read.
    (CVE-2020-11526)

  - An issue was discovered in FreeRDP before 2.1.1. An out-of-bounds (OOB) read vulnerability has been
    detected in ntlm_read_ChallengeMessage in winpr/libwinpr/sspi/NTLM/ntlm_message.c. (CVE-2020-13396)

  - An issue was discovered in FreeRDP before 2.1.1. An out-of-bounds (OOB) read vulnerability has been
    detected in security_fips_decrypt in libfreerdp/core/security.c due to an uninitialized value.
    (CVE-2020-13397)

  - An issue was discovered in FreeRDP before 2.1.1. An out-of-bounds (OOB) write vulnerability has been
    detected in crypto_rsa_common in libfreerdp/crypto/crypto.c. (CVE-2020-13398)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4382-2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13398");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:freerdp-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-cache1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-client1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-codec1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-common1.1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-core1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-crypto1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-gdi1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-locale1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-plugins-standard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-primitives1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-rail1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfreerdp-utils1.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-asn1-0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-bcrypt0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-credentials0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-credui0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-crt0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-crypto0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-dsparse0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-environment0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-error0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-file0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-handle0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-heap0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-input0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-interlocked0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-io0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-library0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-path0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-pipe0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-pool0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-registry0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-rpc0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-sspi0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-sspicli0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-synch0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-sysinfo0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-thread0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-timezone0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-utils0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-winhttp0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libwinpr-winsock0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxfreerdp-client1.1");
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
if (! preg(pattern:"^(18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '18.04', 'pkgname': 'freerdp-x11', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-cache1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-client1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-codec1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-common1.1.0', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-core1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-crypto1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-dev', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-gdi1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-locale1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-plugins-standard', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-primitives1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-rail1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libfreerdp-utils1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-asn1-0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-bcrypt0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-credentials0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-credui0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-crt0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-crypto0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-dev', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-dsparse0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-environment0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-error0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-file0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-handle0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-heap0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-input0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-interlocked0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-io0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-library0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-path0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-pipe0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-pool0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-registry0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-rpc0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-sspi0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-sspicli0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-synch0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-sysinfo0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-thread0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-timezone0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-utils0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-winhttp0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libwinpr-winsock0.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'},
    {'osver': '18.04', 'pkgname': 'libxfreerdp-client1.1', 'pkgver': '1.1.0~git20140921.1.440916e+dfsg1-15ubuntu1.18.04.2'}
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
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp-x11 / libfreerdp-cache1.1 / libfreerdp-client1.1 / etc');
}