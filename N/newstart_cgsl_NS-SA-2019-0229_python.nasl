#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0229. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132508);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-14647",
    "CVE-2019-5010",
    "CVE-2019-9740",
    "CVE-2019-9947",
    "CVE-2019-9948"
  );
  script_bugtraq_id(
    105396,
    106636,
    107466,
    107549,
    107555
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : python Multiple Vulnerabilities (NS-SA-2019-0229)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has python packages installed that are affected by
multiple vulnerabilities:

  - An exploitable denial-of-service vulnerability exists in
    the X509 certificate parser of Python.org Python 2.7.11
    / 3.6.6. A specially crafted X509 certificate can cause
    a NULL pointer dereference, resulting in a denial of
    service. An attacker can initiate or accept TLS
    connections using crafted certificates to trigger this
    vulnerability. (CVE-2019-5010)

  - urllib in Python 2.x through 2.7.16 supports the
    local_file: scheme, which makes it easier for remote
    attackers to bypass protection mechanisms that blacklist
    file: URIs, as demonstrated by triggering a
    urllib.urlopen('local_file:///etc/passwd') call.
    (CVE-2019-9948)

  - An issue was discovered in urllib2 in Python 2.x through
    2.7.16 and urllib in Python 3.x through 3.7.3. CRLF
    injection is possible if the attacker controls a url
    parameter, as demonstrated by the first argument to
    urllib.request.urlopen with \r\n (specifically in the
    query string after a ? character) followed by an HTTP
    header or a Redis command. (CVE-2019-9740)

  - An issue was discovered in urllib2 in Python 2.x through
    2.7.16 and urllib in Python 3.x through 3.7.3. CRLF
    injection is possible if the attacker controls a url
    parameter, as demonstrated by the first argument to
    urllib.request.urlopen with \r\n (specifically in the
    path component of a URL that lacks a ? character)
    followed by an HTTP header or a Redis command. This is
    similar to the CVE-2019-9740 query string issue.
    (CVE-2019-9947)

  - Python's elementtree C accelerator failed to initialise
    Expat's hash salt during initialization. This could make
    it easy to conduct denial of service attacks against
    Expat by constructing an XML document that would cause
    pathological hash collisions in Expat's internal data
    structures, consuming large amounts CPU and RAM. Python
    3.8, 3.7, 3.6, 3.5, 3.4, 2.7 are believed to be
    vulnerable. (CVE-2018-14647)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0229");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL python packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9948");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "python-2.7.5-86.el7.cgslv5_5.0.1.g224a68e.lite",
    "python-debug-2.7.5-86.el7.cgslv5_5.0.1.g224a68e.lite",
    "python-debuginfo-2.7.5-86.el7.cgslv5_5.0.1.g224a68e.lite",
    "python-devel-2.7.5-86.el7.cgslv5_5.0.1.g224a68e.lite",
    "python-libs-2.7.5-86.el7.cgslv5_5.0.1.g224a68e.lite",
    "python-test-2.7.5-86.el7.cgslv5_5.0.1.g224a68e.lite",
    "python-tools-2.7.5-86.el7.cgslv5_5.0.1.g224a68e.lite",
    "tkinter-2.7.5-86.el7.cgslv5_5.0.1.g224a68e.lite"
  ],
  "CGSL MAIN 5.05": [
    "python-2.7.5-86.el7.cgslv5_5.0.1.gb73d78f",
    "python-debug-2.7.5-86.el7.cgslv5_5.0.1.gb73d78f",
    "python-debuginfo-2.7.5-86.el7.cgslv5_5.0.1.gb73d78f",
    "python-devel-2.7.5-86.el7.cgslv5_5.0.1.gb73d78f",
    "python-libs-2.7.5-86.el7.cgslv5_5.0.1.gb73d78f",
    "python-test-2.7.5-86.el7.cgslv5_5.0.1.gb73d78f",
    "python-tools-2.7.5-86.el7.cgslv5_5.0.1.gb73d78f",
    "tkinter-2.7.5-86.el7.cgslv5_5.0.1.gb73d78f"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python");
}
