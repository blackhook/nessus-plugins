#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0039. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127212);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-1000007",
    "CVE-2018-1000120",
    "CVE-2018-1000121",
    "CVE-2018-1000122",
    "CVE-2018-1000301"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : curl Multiple Vulnerabilities (NS-SA-2019-0039)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has curl packages installed that are affected by
multiple vulnerabilities:

  - curl version curl 7.20.0 to and including curl 7.59.0
    contains a CWE-126: Buffer Over-read vulnerability in
    denial of service that can result in curl can be tricked
    into reading data beyond the end of a heap based buffer
    used to store downloaded RTSP content.. This
    vulnerability appears to have been fixed in curl <
    7.20.0 and curl >= 7.60.0. (CVE-2018-1000301)

  - It was found that libcurl did not safely parse FTP URLs
    when using the CURLOPT_FTP_FILEMETHOD method. An
    attacker, able to provide a specially crafted FTP URL to
    an application using libcurl, could write a NULL byte at
    an arbitrary location, resulting in a crash or an
    unspecified behavior. (CVE-2018-1000120)

  - A NULL pointer dereference flaw was found in the way
    libcurl checks values returned by the openldap
    ldap_get_attribute_ber() function. A malicious LDAP
    server could use this flaw to crash a libcurl client
    application via a specially crafted LDAP reply.
    (CVE-2018-1000121)

  - A buffer over-read exists in curl 7.20.0 to and
    including curl 7.58.0 in the RTSP+RTP handling code that
    allows an attacker to cause a denial of service or
    information leakage (CVE-2018-1000122)

  - It was found that curl and libcurl might send their
    Authentication header to a third party HTTP server upon
    receiving an HTTP REDIRECT reply. This could leak
    authentication token to external entities.
    (CVE-2018-1000007)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0039");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL curl packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000120");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");


  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/24");
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

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "curl-7.29.0-51.el7",
    "curl-debuginfo-7.29.0-51.el7",
    "libcurl-7.29.0-51.el7",
    "libcurl-devel-7.29.0-51.el7"
  ],
  "CGSL MAIN 5.04": [
    "curl-7.29.0-51.el7",
    "curl-debuginfo-7.29.0-51.el7",
    "libcurl-7.29.0-51.el7",
    "libcurl-devel-7.29.0-51.el7"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl");
}
