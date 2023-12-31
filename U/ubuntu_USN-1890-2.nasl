#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-1890-2. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67186);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id(
    "CVE-2013-1682",
    "CVE-2013-1683",
    "CVE-2013-1684",
    "CVE-2013-1685",
    "CVE-2013-1686",
    "CVE-2013-1687",
    "CVE-2013-1688",
    "CVE-2013-1690",
    "CVE-2013-1692",
    "CVE-2013-1693",
    "CVE-2013-1694",
    "CVE-2013-1695",
    "CVE-2013-1696",
    "CVE-2013-1697",
    "CVE-2013-1698",
    "CVE-2013-1699"
  );
  script_bugtraq_id(
    60765,
    60766,
    60768,
    60773,
    60774,
    60776,
    60777,
    60778,
    60779,
    60783,
    60784,
    60785,
    60787,
    60788,
    60789,
    60790
  );
  script_xref(name:"USN", value:"1890-2");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"Ubuntu 12.04 LTS / 12.10 / 13.04 : firefox regression (USN-1890-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"USN-1890-1 fixed vulnerabilities in Firefox. This update introduced a
regression which sometimes resulted in Firefox using the wrong network
proxy settings. This update fixes the problem.

We apologize for the inconvenience.

Multiple memory safety issues were discovered in Firefox. If the user
were tricked into opening a specially crafted page, an attacker could
possibly exploit these to cause a denial of service via application
crash, or potentially execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2013-1682, CVE-2013-1683)

Abhishek Arya discovered multiple use-after-free bugs. If
the user were tricked into opening a specially crafted page,
an attacker could possibly exploit these to execute
arbitrary code with the privileges of the user invoking
Firefox. (CVE-2013-1684, CVE-2013-1685, CVE-2013-1686)

Mariusz Mlynski discovered that user defined code within the
XBL scope of an element could be made to bypass System Only
Wrappers (SOW). An attacker could potentially exploit this
to execute arbitrary code with the privileges of the user
invoking Firefox. (CVE-2013-1687)

Mariusz Mlynski discovered that the profiler user interface
incorrectly handled data from the profiler. If the user
examined profiler output on a specially crafted page, an
attacker could potentially exploit this to execute arbitrary
code with the privileges of the user invoking Firefox.
(CVE-2013-1688)

A crash was discovered when reloading a page that contained
content using the onreadystatechange event. An attacker
could potentially exploit this to execute arbitrary code
with the privileges of the user invoking Firefox
(CVE-2013-1690)

Johnathan Kuskos discovered that Firefox sent data in the
body of XMLHttpRequest HEAD requests. An attacker could
exploit this to conduct Cross-Site Request Forgery (CSRF)
attacks. (CVE-2013-1692)

Paul Stone discovered a timing flaw in the processing of SVG
images with filters. An attacker could exploit this to view
sensitive information. (CVE-2013-1693)

Boris Zbarsky discovered a flaw in PreserveWrapper. An
attacker could potentially exploit this to cause a denial of
service via application crash, or execute code with the
privileges of the user invoking Firefox. (CVE-2013-1694)

Bob Owen discovered that a sandboxed iframe could use a
frame element to bypass its own restrictions.
(CVE-2013-1695)

Frederic Buclin discovered that the X-Frame-Options header
is ignored in multi-part responses. An attacker could
potentially exploit this to conduct clickjacking attacks.
(CVE-2013-1696)

It was discovered that XrayWrappers could be bypassed to
call content-defined methods in certain circumstances. An
attacker could exploit this to cause undefined behaviour.
(CVE-2013-1697)

Matt Wobensmith discovered that the getUserMedia permission
dialog displayed the wrong domain in certain circumstances.
An attacker could potentially exploit this to trick the user
in to giving a malicious site access to their microphone or
camera. (CVE-2013-1698)

It was discovered that the measures for preventing homograph
attacks using Internationalized Domain Names (IDN) were not
sufficient for certain Top Level Domains (TLD). An attacker
could potentially exploit this to conduct URL spoofing and
phishing attacks. (CVE-2013-1699).

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://usn.ubuntu.com/1890-2/");
  script_set_attribute(attribute:"solution", value:
"Update the affected firefox package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox onreadystatechange Event DocumentViewerImpl Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:12.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:13.04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2013-2022 Canonical, Inc. / NASL script (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! preg(pattern:"^(12\.04|12\.10|13\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 12.04 / 12.10 / 13.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"12.04", pkgname:"firefox", pkgver:"22.0+build2-0ubuntu0.12.04.2")) flag++;
if (ubuntu_check(osver:"12.10", pkgname:"firefox", pkgver:"22.0+build2-0ubuntu0.12.10.2")) flag++;
if (ubuntu_check(osver:"13.04", pkgname:"firefox", pkgver:"22.0+build2-0ubuntu0.13.04.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");
}
