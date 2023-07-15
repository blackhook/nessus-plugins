#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4557-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141092);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2016-0762",
    "CVE-2016-5018",
    "CVE-2016-6794",
    "CVE-2016-6796",
    "CVE-2016-6797",
    "CVE-2016-6816",
    "CVE-2016-8735"
  );
  script_bugtraq_id(
    93939,
    93940,
    93942,
    93943,
    93944,
    94461,
    94463
  );
  script_xref(name:"USN", value:"4557-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"Ubuntu 16.04 LTS : Tomcat vulnerabilities (USN-4557-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-4557-1 advisory.

  - The Realm implementations in Apache Tomcat versions 9.0.0.M1 to 9.0.0.M9, 8.5.0 to 8.5.4, 8.0.0.RC1 to
    8.0.36, 7.0.0 to 7.0.70 and 6.0.0 to 6.0.45 did not process the supplied password if the supplied user
    name did not exist. This made a timing attack possible to determine valid user names. Note that the
    default configuration includes the LockOutRealm which makes exploitation of this vulnerability harder.
    (CVE-2016-0762)

  - In Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to 8.5.4, 8.0.0.RC1 to 8.0.36, 7.0.0 to 7.0.70 and 6.0.0 to
    6.0.45 a malicious web application was able to bypass a configured SecurityManager via a Tomcat utility
    method that was accessible to web applications. (CVE-2016-5018)

  - When a SecurityManager is configured, a web application's ability to read system properties should be
    controlled by the SecurityManager. In Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to 8.5.4, 8.0.0.RC1 to
    8.0.36, 7.0.0 to 7.0.70, 6.0.0 to 6.0.45 the system property replacement feature for configuration files
    could be used by a malicious web application to bypass the SecurityManager and read system properties that
    should not be visible. (CVE-2016-6794)

  - A malicious web application running on Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to 8.5.4, 8.0.0.RC1 to
    8.0.36, 7.0.0 to 7.0.70 and 6.0.0 to 6.0.45 was able to bypass a configured SecurityManager via
    manipulation of the configuration parameters for the JSP Servlet. (CVE-2016-6796)

  - The ResourceLinkFactory implementation in Apache Tomcat 9.0.0.M1 to 9.0.0.M9, 8.5.0 to 8.5.4, 8.0.0.RC1 to
    8.0.36, 7.0.0 to 7.0.70 and 6.0.0 to 6.0.45 did not limit web application access to global JNDI resources
    to those resources explicitly linked to the web application. Therefore, it was possible for a web
    application to access any global JNDI resource whether an explicit ResourceLink had been configured or
    not. (CVE-2016-6797)

  - The code in Apache Tomcat 9.0.0.M1 to 9.0.0.M11, 8.5.0 to 8.5.6, 8.0.0.RC1 to 8.0.38, 7.0.0 to 7.0.72, and
    6.0.0 to 6.0.47 that parsed the HTTP request line permitted invalid characters. This could be exploited,
    in conjunction with a proxy that also permitted the invalid characters but with a different
    interpretation, to inject data into the HTTP response. By manipulating the HTTP response the attacker
    could poison a web-cache, perform an XSS attack and/or obtain sensitive information from requests other
    then their own. (CVE-2016-6816)

  - Remote code execution is possible with Apache Tomcat before 6.0.48, 7.x before 7.0.73, 8.x before 8.0.39,
    8.5.x before 8.5.7, and 9.x before 9.0.0.M12 if JmxRemoteLifecycleListener is used and an attacker can
    reach JMX ports. The issue exists because this listener wasn't updated for consistency with the
    CVE-2016-3427 Oracle patch that affected credential types. (CVE-2016-8735)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4557-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected libservlet2.5-java package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8735");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libservlet2.5-java");
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
if (! preg(pattern:"^(16\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '16.04', 'pkgname': 'libservlet2.5-java', 'pkgver': '6.0.45+dfsg-1ubuntu0.1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libservlet2.5-java');
}