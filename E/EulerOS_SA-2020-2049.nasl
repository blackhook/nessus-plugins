#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140997);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2019-16785",
    "CVE-2019-16786",
    "CVE-2019-16789"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : python-waitress (EulerOS-SA-2020-2049)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python-waitress package installed,
the EulerOS Virtualization for ARM 64 installation on the remote host
is affected by the following vulnerabilities :

  - Waitress through version 1.3.1 would parse the
    Transfer-Encoding header and only look for a single
    string value, if that value was not chunked it would
    fall through and use the Content-Length header instead.
    According to the HTTP standard Transfer-Encoding should
    be a comma separated list, with the inner-most encoding
    first, followed by any further transfer codings, ending
    with chunked. Requests sent with: 'Transfer-Encoding:
    gzip, chunked' would incorrectly get ignored, and the
    request would use a Content-Length header instead to
    determine the body size of the HTTP message. This could
    allow for Waitress to treat a single request as
    multiple requests in the case of HTTP pipelining. This
    issue is fixed in Waitress 1.4.0.(CVE-2019-16786)

  - Waitress through version 1.3.1 implemented a 'MAY' part
    of the RFC7230 which states: 'Although the line
    terminator for the start-line and header fields is the
    sequence CRLF, a recipient MAY recognize a single LF as
    a line terminator and ignore any preceding CR.'
    Unfortunately if a front-end server does not parse
    header fields with an LF the same way as it does those
    with a CRLF it can lead to the front-end and the
    back-end server parsing the same HTTP message in two
    different ways. This can lead to a potential for HTTP
    request smuggling/splitting whereby Waitress may see
    two requests while the front-end server only sees a
    single HTTP message. This issue is fixed in Waitress
    1.4.0.(CVE-2019-16785)

  - In Waitress through version 1.4.0, if a proxy server is
    used in front of waitress, an invalid request may be
    sent by an attacker that bypasses the front-end and is
    parsed differently by waitress leading to a potential
    for HTTP request smuggling. Specially crafted requests
    containing special whitespace characters in the
    Transfer-Encoding header would get parsed by Waitress
    as being a chunked request, but a front-end server
    would use the Content-Length instead as the
    Transfer-Encoding header is considered invalid due to
    containing invalid characters. If a front-end server
    does HTTP pipelining to a backend Waitress server this
    could lead to HTTP request splitting which may lead to
    potential cache poisoning or unexpected information
    disclosure. This issue is fixed in Waitress 1.4.1
    through more strict HTTP field
    validation.(CVE-2019-16789)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2049
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c3a6983a");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-waitress packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-waitress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["python2-waitress-1.1.0-6.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-waitress");
}
