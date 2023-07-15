#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5946-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172496);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/14");

  script_cve_id(
    "CVE-2021-39139",
    "CVE-2021-39140",
    "CVE-2021-39141",
    "CVE-2021-39144",
    "CVE-2021-39145",
    "CVE-2021-39146",
    "CVE-2021-39147",
    "CVE-2021-39148",
    "CVE-2021-39149",
    "CVE-2021-39150",
    "CVE-2021-39151",
    "CVE-2021-39152",
    "CVE-2021-39153",
    "CVE-2021-39154",
    "CVE-2022-41966"
  );
  script_xref(name:"USN", value:"5946-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/31");
  script_xref(name:"CEA-ID", value:"CEA-2022-0035");

  script_name(english:"Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS : XStream vulnerabilities (USN-5946-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM / 18.04 LTS / 20.04 LTS / 22.04 LTS host has a package installed that is affected by
multiple vulnerabilities as referenced in the USN-5946-1 advisory.

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream. A user is only affected if using the version out of the box with
    JDK 1.7u21 or below. However, this scenario can be adjusted easily to an external Xalan that works
    regardless of the version of the Java runtime. No user is affected, who followed the recommendation to
    setup XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18
    uses no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39139)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to allocate 100% CPU time on the target system depending on CPU
    type or parallel execution of such a payload resulting in a denial of service only by manipulating the
    processed input stream. No user is affected, who followed the recommendation to setup XStream's security
    framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a
    blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39140)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses
    no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39141,
    CVE-2021-39145, CVE-2021-39146, CVE-2021-39147, CVE-2021-39148, CVE-2021-39149, CVE-2021-39151,
    CVE-2021-39154)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker has sufficient rights to execute commands of the host only by
    manipulating the processed input stream. No user is affected, who followed the recommendation to setup
    XStream's security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses
    no longer a blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39144)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to request data from internal resources that are not publicly
    available only by manipulating the processed input stream with a Java runtime version 14 to 8. No user is
    affected, who followed the recommendation to setup XStream's security framework with a whitelist limited
    to the minimal required types. If you rely on XStream's default blacklist of the [Security
    Framework](https://x-stream.github.io/security.html#framework), you will have to use at least version
    1.4.18. (CVE-2021-39150, CVE-2021-39152)

  - XStream is a simple library to serialize objects to XML and back again. In affected versions this
    vulnerability may allow a remote attacker to load and execute arbitrary code from a remote host only by
    manipulating the processed input stream, if using the version out of the box with Java runtime version 14
    to 8 or with JavaFX installed. No user is affected, who followed the recommendation to setup XStream's
    security framework with a whitelist limited to the minimal required types. XStream 1.4.18 uses no longer a
    blacklist by default, since it cannot be secured for general purpose. (CVE-2021-39153)

  - XStream serializes Java objects to XML and back again. Versions prior to 1.4.20 may allow a remote
    attacker to terminate the application with a stack overflow error, resulting in a denial of service only
    via manipulation the processed input stream. The attack uses the hash code implementation for collections
    and maps to force recursive hash calculation causing a stack overflow. This issue is patched in version
    1.4.20 which handles the stack overflow and raises an InputManipulationException instead. A potential
    workaround for users who only use HashMap or HashSet and whose XML refers these only as default map or
    set, is to change the default implementation of java.util.Map and java.util per the code example in the
    referenced advisory. However, this implies that your application does not care about the implementation of
    the map and all elements are comparable. (CVE-2022-41966)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5946-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libxstream-java package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39139");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VMware NSX Manager XStream unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxstream-java");
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
if (! preg(pattern:"^(16\.04|18\.04|20\.04|22\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04 / 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libxstream-java', 'pkgver': '1.4.8-1ubuntu0.1+esm1'},
    {'osver': '18.04', 'pkgname': 'libxstream-java', 'pkgver': '1.4.11.1-1+deb10u4build0.18.04.1'},
    {'osver': '20.04', 'pkgname': 'libxstream-java', 'pkgver': '1.4.11.1-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'libxstream-java', 'pkgver': '1.4.18-2ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libxstream-java');
}
