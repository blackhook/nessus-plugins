#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3665-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(110264);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/11");

  script_cve_id("CVE-2017-12616", "CVE-2017-12617", "CVE-2017-15706", "CVE-2018-1304", "CVE-2018-1305", "CVE-2018-8014");
  script_xref(name:"USN", value:"3665-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Ubuntu 14.04 LTS / 16.04 LTS / 17.10 / 18.04 LTS : Tomcat vulnerabilities (USN-3665-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description",
    value:
"It was discovered that Tomcat incorrectly handled being configured
with HTTP PUTs enabled. A remote attacker could use this issue to
upload a JSP file to the server and execute arbitrary code. This issue
only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 17.10.
(CVE-2017-12616, CVE-2017-12617)

It was discovered that Tomcat contained incorrect documentation
regarding description of the search algorithm used by the CGI Servlet
to identify which script to execute. This issue only affected Ubuntu
17.10. (CVE-2017-15706)

It was discovered that Tomcat incorrectly handled en empty string URL
pattern in security constraint definitions. A remote attacker could
possibly use this issue to gain access to web application resources,
contrary to expectations. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2018-1304)

It was discovered that Tomcat incorrectly handled applying certain
security constraints. A remote attacker could possibly access certain
resources, contrary to expectations. This issue only affected Ubuntu
14.04 LTS, Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2018-1305)

It was discovered that the Tomcat CORS filter default settings were
insecure and would enable 'supportsCredentials' for all origins,
contrary to expectations. (CVE-2018-8014).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3665-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8014");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat VirtualDirContext Class File Handling Remote JSP Source Code Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat7-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libtomcat8-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:tomcat8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:14.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:17.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2018-2023 Canonical, Inc. / NASL script (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(14\.04|16\.04|17\.10|18\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 14.04 / 16.04 / 17.10 / 18.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var flag = 0;

if (ubuntu_check(osver:"14.04", pkgname:"libtomcat7-java", pkgver:"7.0.52-1ubuntu0.14")) flag++;
if (ubuntu_check(osver:"14.04", pkgname:"tomcat7", pkgver:"7.0.52-1ubuntu0.14")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"libtomcat8-java", pkgver:"8.0.32-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"16.04", pkgname:"tomcat8", pkgver:"8.0.32-1ubuntu1.6")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"libtomcat8-java", pkgver:"8.5.21-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"17.10", pkgname:"tomcat8", pkgver:"8.5.21-1ubuntu1.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libtomcat8-java", pkgver:"8.5.30-1ubuntu1.2")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"tomcat8", pkgver:"8.5.30-1ubuntu1.2")) flag++;

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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtomcat7-java / libtomcat8-java / tomcat7 / tomcat8");
}
