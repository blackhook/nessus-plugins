##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162437);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/22");

  script_cve_id("CVE-2022-24761");

  script_name(english:"EulerOS 2.0 SP8 : python-waitress (EulerOS-SA-2022-1948)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python-waitress package installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

  - Waitress is a Web Server Gateway Interface server for Python 2 and 3. When using Waitress versions 2.1.0
    and prior behind a proxy that does not properly validate the incoming HTTP request matches the RFC7230
    standard, Waitress and the frontend proxy may disagree on where one request starts and where it ends. This
    would allow requests to be smuggled via the front-end proxy to waitress and later behavior. There are two
    classes of vulnerability that may lead to request smuggling that are addressed by this advisory: The use
    of Python's `int()` to parse strings into integers, leading to `+10` to be parsed as `10`, or `0x01` to be
    parsed as `1`, where as the standard specifies that the string should contain only digits or hex digits;
    and Waitress does not support chunk extensions, however it was discarding them without validating that
    they did not contain illegal characters. This vulnerability has been patched in Waitress 2.1.1. A
    workaround is available. When deploying a proxy in front of waitress, turning on any and all functionality
    to make sure that the request matches the RFC7230 standard. Certain proxy servers may not have this
    functionality though and users are encouraged to upgrade to the latest version of waitress instead.
    (CVE-2022-24761)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1948
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2118210e");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-waitress packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24761");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-waitress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

var flag = 0;

var pkgs = [
  "python2-waitress-1.1.0-6.h1.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-waitress");
}
