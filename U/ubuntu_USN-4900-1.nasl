##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4900-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148295);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2021-3474",
    "CVE-2021-3475",
    "CVE-2021-3476",
    "CVE-2021-3477",
    "CVE-2021-3478",
    "CVE-2021-3479"
  );
  script_xref(name:"USN", value:"4900-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 : OpenEXR vulnerabilities (USN-4900-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 host has packages installed that are affected by multiple
vulnerabilities as referenced in the USN-4900-1 advisory.

  - There's a flaw in OpenEXR in versions before 3.0.0-beta. A crafted input file that is processed by OpenEXR
    could cause a shift overflow in the FastHufDecoder, potentially leading to problems with application
    availability. (CVE-2021-3474)

  - There is a flaw in OpenEXR in versions before 3.0.0-beta. An attacker who can submit a crafted file to be
    processed by OpenEXR could cause an integer overflow, potentially leading to problems with application
    availability. (CVE-2021-3475)

  - A flaw was found in OpenEXR's B44 uncompression functionality in versions before 3.0.0-beta. An attacker
    who is able to submit a crafted file to OpenEXR could trigger shift overflows, potentially affecting
    application availability. (CVE-2021-3476)

  - There's a flaw in OpenEXR's deep tile sample size calculations in versions before 3.0.0-beta. An attacker
    who is able to submit a crafted file to be processed by OpenEXR could trigger an integer overflow,
    subsequently leading to an out-of-bounds read. The greatest risk of this flaw is to application
    availability. (CVE-2021-3477)

  - There's a flaw in OpenEXR's scanline input file functionality in versions before 3.0.0-beta. An attacker
    able to submit a crafted file to be processed by OpenEXR could consume excessive system memory. The
    greatest impact of this flaw is to system availability. (CVE-2021-3478)

  - There's a flaw in OpenEXR's Scanline API functionality in versions before 3.0.0-beta. An attacker who is
    able to submit a crafted file to be processed by OpenEXR could trigger excessive consumption of memory,
    resulting in an impact to system availability. (CVE-2021-3479)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4900-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3476");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3479");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenexr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenexr22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenexr24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libopenexr25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:openexr");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'libopenexr-dev', 'pkgver': '2.2.0-10ubuntu2.6'},
    {'osver': '16.04', 'pkgname': 'libopenexr22', 'pkgver': '2.2.0-10ubuntu2.6'},
    {'osver': '16.04', 'pkgname': 'openexr', 'pkgver': '2.2.0-10ubuntu2.6'},
    {'osver': '18.04', 'pkgname': 'libopenexr-dev', 'pkgver': '2.2.0-11.1ubuntu1.6'},
    {'osver': '18.04', 'pkgname': 'libopenexr22', 'pkgver': '2.2.0-11.1ubuntu1.6'},
    {'osver': '18.04', 'pkgname': 'openexr', 'pkgver': '2.2.0-11.1ubuntu1.6'},
    {'osver': '20.04', 'pkgname': 'libopenexr-dev', 'pkgver': '2.3.0-6ubuntu0.5'},
    {'osver': '20.04', 'pkgname': 'libopenexr24', 'pkgver': '2.3.0-6ubuntu0.5'},
    {'osver': '20.04', 'pkgname': 'openexr', 'pkgver': '2.3.0-6ubuntu0.5'},
    {'osver': '20.10', 'pkgname': 'libopenexr-dev', 'pkgver': '2.5.3-2ubuntu0.2'},
    {'osver': '20.10', 'pkgname': 'libopenexr25', 'pkgver': '2.5.3-2ubuntu0.2'},
    {'osver': '20.10', 'pkgname': 'openexr', 'pkgver': '2.5.3-2ubuntu0.2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libopenexr-dev / libopenexr22 / libopenexr24 / libopenexr25 / openexr');
}