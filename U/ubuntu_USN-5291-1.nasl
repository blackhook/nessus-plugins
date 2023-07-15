#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5291-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158134);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2021-23177", "CVE-2021-31566", "CVE-2021-36976");
  script_xref(name:"USN", value:"5291-1");

  script_name(english:"Ubuntu 20.04 LTS / 21.10 : libarchive vulnerabilities (USN-5291-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 21.10 host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5291-1 advisory.

  - libarchive 3.4.1 through 3.5.1 has a use-after-free in copy_string (called from do_uncompress_block and
    process_block). (CVE-2021-36976)

  - An improper link resolution flaw while extracting an archive can lead to changing the access control list
    (ACL) of the target of the link. An attacker may provide a malicious archive to a victim user, who would
    trigger this flaw when trying to extract the archive. A local attacker may use this flaw to change the ACL
    of a file on the system and gain more privileges. (CVE-2021-23177)

  - An improper link resolution flaw can occur while extracting an archive leading to changing modes, times,
    access control lists, and flags of a file outside of the archive. An attacker may provide a malicious
    archive to a victim user, who would trigger this flaw when trying to extract the archive. A local attacker
    may use this flaw to gain more privileges in a system. (CVE-2021-31566)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5291-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libarchive-dev, libarchive-tools and / or libarchive13 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36976");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-31566");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libarchive-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libarchive-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libarchive13");
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
if (! ('20.04' >< os_release || '21.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 21.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'libarchive-dev', 'pkgver': '3.4.0-2ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libarchive-tools', 'pkgver': '3.4.0-2ubuntu1.1'},
    {'osver': '20.04', 'pkgname': 'libarchive13', 'pkgver': '3.4.0-2ubuntu1.1'},
    {'osver': '21.10', 'pkgname': 'libarchive-dev', 'pkgver': '3.4.3-2ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libarchive-tools', 'pkgver': '3.4.3-2ubuntu0.1'},
    {'osver': '21.10', 'pkgname': 'libarchive13', 'pkgver': '3.4.3-2ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libarchive-dev / libarchive-tools / libarchive13');
}
