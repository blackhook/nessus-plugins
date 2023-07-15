##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4573-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141301);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2014-6053",
    "CVE-2018-7225",
    "CVE-2019-15681",
    "CVE-2020-14397",
    "CVE-2020-14402",
    "CVE-2020-14403",
    "CVE-2020-14404"
  );
  script_bugtraq_id(70092, 103107);
  script_xref(name:"USN", value:"4573-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS : Vino vulnerabilities (USN-4573-1)");
  script_summary(english:"Checks the dpkg output for the updated package");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple
vulnerabilities as referenced in the USN-4573-1 advisory.

  - The rfbProcessClientNormalMessage function in libvncserver/rfbserver.c in LibVNCServer 0.9.9 and earlier
    does not properly handle attempts to send a large amount of ClientCutText data, which allows remote
    attackers to cause a denial of service (memory consumption or daemon crash) via a crafted message that is
    processed by using a single unchecked malloc. (CVE-2014-6053)

  - An issue was discovered in LibVNCServer through 0.9.11. rfbProcessClientNormalMessage() in rfbserver.c
    does not sanitize msg.cct.length, leading to access to uninitialized and potentially sensitive data or
    possibly unspecified other impact (e.g., an integer overflow) via specially crafted VNC packets.
    (CVE-2018-7225)

  - LibVNC commit before d01e1bb4246323ba6fcee3b82ef1faa9b1dac82a contains a memory leak (CWE-655) in VNC
    server code, which allow an attacker to read stack memory and can be abused for information disclosure.
    Combined with another vulnerability, it can be used to leak stack memory and bypass ASLR. This attack
    appear to be exploitable via network connectivity. These vulnerabilities have been fixed in commit
    d01e1bb4246323ba6fcee3b82ef1faa9b1dac82a. (CVE-2019-15681)

  - An issue was discovered in LibVNCServer before 0.9.13. libvncserver/rfbregion.c has a NULL pointer
    dereference. (CVE-2020-14397)

  - An issue was discovered in LibVNCServer before 0.9.13. libvncserver/corre.c allows out-of-bounds access
    via encodings. (CVE-2020-14402)

  - An issue was discovered in LibVNCServer before 0.9.13. libvncserver/hextile.c allows out-of-bounds access
    via encodings. (CVE-2020-14403)

  - An issue was discovered in LibVNCServer before 0.9.13. libvncserver/rre.c allows out-of-bounds access via
    encodings. (CVE-2020-14404)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4573-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected vino package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vino");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'vino', 'pkgver': '3.8.1-0ubuntu9.3'},
    {'osver': '18.04', 'pkgname': 'vino', 'pkgver': '3.22.0-3ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'vino', 'pkgver': '3.22.0-5ubuntu2.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'vino');
}