#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4991-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150858);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2017-8872",
    "CVE-2019-20388",
    "CVE-2020-24977",
    "CVE-2021-3516",
    "CVE-2021-3517",
    "CVE-2021-3518",
    "CVE-2021-3537",
    "CVE-2021-3541"
  );
  script_xref(name:"USN", value:"4991-1");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 / 21.04 : libxml2 vulnerabilities (USN-4991-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 20.10 / 21.04 host has packages installed that are affected by
multiple vulnerabilities as referenced in the USN-4991-1 advisory.

  - The htmlParseTryOrFinish function in HTMLparser.c in libxml2 2.9.4 allows attackers to cause a denial of
    service (buffer over-read) or information disclosure. (CVE-2017-8872)

  - xmlSchemaPreRun in xmlschemas.c in libxml2 2.9.10 allows an xmlSchemaValidateStream memory leak.
    (CVE-2019-20388)

  - GNOME project libxml2 v2.9.10 has a global buffer over-read vulnerability in xmlEncodeEntitiesInternal at
    libxml2/entities.c. The issue has been fixed in commit 50f06b3e. (CVE-2020-24977)

  - There's a flaw in libxml2's xmllint in versions before 2.9.11. An attacker who is able to submit a crafted
    file to be processed by xmllint could trigger a use-after-free. The greatest impact of this flaw is to
    confidentiality, integrity, and availability. (CVE-2021-3516)

  - There is a flaw in the xml entity encoding functionality of libxml2 in versions before 2.9.11. An attacker
    who is able to supply a crafted file to be processed by an application linked with the affected
    functionality of libxml2 could trigger an out-of-bounds read. The most likely impact of this flaw is to
    application availability, with some potential impact to confidentiality and integrity if an attacker is
    able to use memory information to further exploit the application. (CVE-2021-3517)

  - There's a flaw in libxml2 in versions before 2.9.11. An attacker who is able to submit a crafted file to
    be processed by an application linked with libxml2 could trigger a use-after-free. The greatest impact
    from this flaw is to confidentiality, integrity, and availability. (CVE-2021-3518)

  - A vulnerability found in libxml2 in versions before 2.9.11 shows that it did not propagate errors while
    parsing XML mixed content, causing a NULL dereference. If an untrusted XML document was parsed in recovery
    mode and post-validated, the flaw could be used to crash the application. The highest threat from this
    vulnerability is to system availability. (CVE-2021-3537)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4991-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-8872");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:21.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-libxml2");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|20\.10|21\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 20.10 / 21.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'libxml2', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm1'},
    {'osver': '16.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm1'},
    {'osver': '16.04', 'pkgname': 'libxml2-udeb', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm1'},
    {'osver': '16.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm1'},
    {'osver': '16.04', 'pkgname': 'python-libxml2', 'pkgver': '2.9.3+dfsg1-1ubuntu0.7+esm1'},
    {'osver': '18.04', 'pkgname': 'libxml2', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libxml2-udeb', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'python-libxml2', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.4'},
    {'osver': '18.04', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.4+dfsg1-6.1ubuntu1.4'},
    {'osver': '20.04', 'pkgname': 'libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python-libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.04.1'},
    {'osver': '20.10', 'pkgname': 'libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'python-libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.10.2'},
    {'osver': '20.10', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.10+dfsg-5ubuntu0.20.10.2'},
    {'osver': '21.04', 'pkgname': 'libxml2', 'pkgver': '2.9.10+dfsg-6.3ubuntu0.1'},
    {'osver': '21.04', 'pkgname': 'libxml2-dev', 'pkgver': '2.9.10+dfsg-6.3ubuntu0.1'},
    {'osver': '21.04', 'pkgname': 'libxml2-utils', 'pkgver': '2.9.10+dfsg-6.3ubuntu0.1'},
    {'osver': '21.04', 'pkgname': 'python3-libxml2', 'pkgver': '2.9.10+dfsg-6.3ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxml2 / libxml2-dev / libxml2-udeb / libxml2-utils / python-libxml2 / etc');
}
