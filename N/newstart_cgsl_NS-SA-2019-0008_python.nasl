#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0008. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127154);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2007-4965",
    "CVE-2008-2316",
    "CVE-2008-5983",
    "CVE-2010-1634",
    "CVE-2010-2089",
    "CVE-2013-4238"
  );

  script_name(english:"NewStart CGSL MAIN 5.04 : python Multiple Vulnerabilities (NS-SA-2019-0008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 5.04, has python packages installed that are affected by multiple
vulnerabilities:

  - Multiple integer overflows in the imageop module in
    Python 2.5.1 and earlier allow context-dependent
    attackers to cause a denial of service (application
    crash) and possibly obtain sensitive information (memory
    contents) via crafted arguments to (1) the tovideo
    method, and unspecified other vectors related to (2)
    imageop.c, (3) rbgimgmodule.c, and other files, which
    trigger heap-based buffer overflows. (CVE-2007-4965)

  - Integer overflow in _hashopenssl.c in the hashlib module
    in Python 2.5.2 and earlier might allow context-
    dependent attackers to defeat cryptographic digests,
    related to partial hashlib hashing of data exceeding
    4GB. (CVE-2008-2316)

  - Untrusted search path vulnerability in the PySys_SetArgv
    API function in Python 2.6 and earlier, and possibly
    later versions, prepends an empty string to sys.path
    when the argv[0] argument does not contain a path
    separator, which might allow local users to execute
    arbitrary code via a Trojan horse Python file in the
    current working directory. (CVE-2008-5983)

  - Multiple integer overflows in audioop.c in the audioop
    module in Python 2.6, 2.7, 3.1, and 3.2 allow context-
    dependent attackers to cause a denial of service
    (application crash) via a large fragment, as
    demonstrated by a call to audioop.lin2lin with a long
    string in the first argument, leading to a buffer
    overflow. NOTE: this vulnerability exists because of an
    incorrect fix for CVE-2008-3143.5. (CVE-2010-1634)

  - The audioop module in Python 2.7 and 3.2 does not verify
    the relationships between size arguments and byte string
    lengths, which allows context-dependent attackers to
    cause a denial of service (memory corruption and
    application crash) via crafted arguments, as
    demonstrated by a call to audioop.reverse with a one-
    byte string, a different vulnerability than
    CVE-2010-1634. (CVE-2010-2089)

  - The ssl.match_hostname function in the SSL module in
    Python 2.6 through 3.4 does not properly handle a '\0'
    character in a domain name in the Subject Alternative
    Name field of an X.509 certificate, which allows man-in-
    the-middle attackers to spoof arbitrary SSL servers via
    a crafted certificate issued by a legitimate
    Certification Authority, a related issue to
    CVE-2009-2408. (CVE-2013-4238)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0008");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL python packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-2316");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

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

if (release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 5.04": [
    "python-2.7.5-58.el7.cgslv5.0.1.g6d96868",
    "python-debug-2.7.5-58.el7.cgslv5.0.1.g6d96868",
    "python-debuginfo-2.7.5-58.el7.cgslv5.0.1.g6d96868",
    "python-devel-2.7.5-58.el7.cgslv5.0.1.g6d96868",
    "python-libs-2.7.5-58.el7.cgslv5.0.1.g6d96868",
    "python-test-2.7.5-58.el7.cgslv5.0.1.g6d96868",
    "python-tools-2.7.5-58.el7.cgslv5.0.1.g6d96868",
    "tkinter-2.7.5-58.el7.cgslv5.0.1.g6d96868"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
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
