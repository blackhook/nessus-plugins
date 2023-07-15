#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6102-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176324);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2021-21366", "CVE-2022-37616", "CVE-2022-39353");
  script_xref(name:"USN", value:"6102-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 22.10 : xmldom vulnerabilities (USN-6102-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 22.10 host has a package installed that is affected by multiple
vulnerabilities as referenced in the USN-6102-1 advisory.

  - xmldom is a pure JavaScript W3C standard-based (XML DOM Level 2 Core) DOMParser and XMLSerializer module.
    xmldom versions 0.4.0 and older do not correctly preserve system identifiers, FPIs or namespaces when
    repeatedly parsing and serializing maliciously crafted documents. This may lead to unexpected syntactic
    changes during XML processing in some downstream applications. This is fixed in version 0.5.0. As a
    workaround downstream applications can validate the input and reject the maliciously crafted documents.
    (CVE-2021-21366)

  - A prototype pollution vulnerability exists in the function copy in dom.js in the xmldom (published as
    @xmldom/xmldom) package before 0.8.3 for Node.js via the p variable. NOTE: the vendor states we are in
    the process of marking this report as invalid; however, some third parties takes the position that A
    prototype injection/Prototype pollution is not just when global objects are polluted with recursive merge
    or deep cloning but also when a target object is polluted. (CVE-2022-37616)

  - xmldom is a pure JavaScript W3C standard-based (XML DOM Level 2 Core) `DOMParser` and `XMLSerializer`
    module. xmldom parses XML that is not well-formed because it contains multiple top level elements, and
    adds all root nodes to the `childNodes` collection of the `Document`, without reporting any error or
    throwing. This breaks the assumption that there is only a single root node in the tree, which led to
    issuance of CVE-2022-39299 as it is a potential issue for dependents. Update to @xmldom/xmldom@~0.7.7,
    @xmldom/xmldom@~0.8.4 (dist-tag latest) or @xmldom/xmldom@>=0.9.0-beta.4 (dist-tag next). As a workaround,
    please one of the following approaches depending on your use case: instead of searching for elements in
    the whole DOM, only search in the `documentElement`or reject a document with a document that has more then
    1 `childNode`. (CVE-2022-39353)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6102-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected node-xmldom package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21366");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39353");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:node-xmldom");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(20\.04|22\.04|22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'node-xmldom', 'pkgver': '0.1.27+ds-1+deb10u2build0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'node-xmldom', 'pkgver': '0.7.5-1ubuntu0.22.04.1'},
    {'osver': '22.10', 'pkgname': 'node-xmldom', 'pkgver': '0.7.5-1ubuntu0.22.10.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'node-xmldom');
}
