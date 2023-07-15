#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4536-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140786);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2017-15736",
    "CVE-2019-11071",
    "CVE-2019-16391",
    "CVE-2019-16392",
    "CVE-2019-16393",
    "CVE-2019-16394",
    "CVE-2019-19830"
  );
  script_xref(name:"USN", value:"4536-1");

  script_name(english:"Ubuntu 18.04 LTS : SPIP vulnerabilities (USN-4536-1)");
  script_summary(english:"Checks the dpkg output for the updated package");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4536-1 advisory.

  - Cross-site scripting (XSS) vulnerability (stored) in SPIP before 3.1.7 allows remote attackers to inject
    arbitrary web script or HTML via a crafted string, as demonstrated by a PGP field, related to
    prive/objets/contenu/auteur.html and ecrire/inc/texte_mini.php. (CVE-2017-15736)

  - SPIP 3.1 before 3.1.10 and 3.2 before 3.2.4 allows authenticated visitors to execute arbitrary code on the
    host server because var_memotri is mishandled. (CVE-2019-11071)

  - SPIP before 3.1.11 and 3.2 before 3.2.5 allows authenticated visitors to modify any published content and
    execute other modifications in the database. This is related to ecrire/inc/meta.php and
    ecrire/inc/securiser_action.php. (CVE-2019-16391)

  - SPIP before 3.1.11 and 3.2 before 3.2.5 allows prive/formulaires/login.php XSS via error messages.
    (CVE-2019-16392)

  - SPIP before 3.1.11 and 3.2 before 3.2.5 mishandles redirect URLs in ecrire/inc/headers.php with a %0D,
    %0A, or %20 character. (CVE-2019-16393)

  - SPIP before 3.1.11 and 3.2 before 3.2.5 provides different error messages from the password-reminder page
    depending on whether an e-mail address exists, which might help attackers to enumerate subscribers.
    (CVE-2019-16394)

  - _core_/plugins/medias in SPIP 3.2.x before 3.2.7 allows remote authenticated authors to inject content
    into the database. (CVE-2019-19830)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4536-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected spip package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11071");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:spip");
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
    {'osver': '18.04', 'pkgname': 'spip', 'pkgver': '3.1.4-4~deb9u3build0.18.04.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'spip');
}