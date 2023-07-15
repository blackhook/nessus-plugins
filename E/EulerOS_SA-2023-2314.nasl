#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178077);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/09");

  script_cve_id("CVE-2023-24534", "CVE-2023-24537", "CVE-2023-24538");

  script_name(english:"EulerOS 2.0 SP9 : golang (EulerOS-SA-2023-2314)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the golang packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - HTTP and MIME header parsing can allocate large amounts of memory, even when parsing small inputs,
    potentially leading to a denial of service. Certain unusual patterns of input data can cause the common
    function used to parse HTTP and MIME headers to allocate substantially more memory than required to hold
    the parsed headers. An attacker can exploit this behavior to cause an HTTP server to allocate large
    amounts of memory from a small request, potentially leading to memory exhaustion and a denial of service.
    With fix, header parsing now correctly allocates only the memory required to hold parsed headers.
    (CVE-2023-24534)

  - Calling any of the Parse functions on Go source code which contains //line directives with very large line
    numbers can cause an infinite loop due to integer overflow. (CVE-2023-24537)

  - Templates do not properly consider backticks (`) as Javascript string delimiters, and do not escape them
    as expected. Backticks are used, since ES6, for JS template literals. If a template contains a Go template
    action within a Javascript template literal, the contents of the action can be used to terminate the
    literal, injecting arbitrary Javascript code into the Go template. As ES6 template literals are rather
    complex, and themselves can do string interpolation, the decision was made to simply disallow Go template
    actions from being used inside of them (e.g. 'var a = {{.}}'), since there is no obviously safe way to
    allow this behavior. This takes the same approach as github.com/google/safehtml. With fix, Template.Parse
    returns an Error when it encounters templates like this, with an ErrorCode of value 12. This ErrorCode is
    currently unexported, but will be exported in the release of Go 1.21. Users who rely on the previous
    behavior can re-enable it using the GODEBUG flag jstmpllitinterp=1, with the caveat that backticks will
    now be escaped. This should be used with caution. (CVE-2023-24538)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2314
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36bdc016");
  script_set_attribute(attribute:"solution", value:
"Update the affected golang packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24538");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:golang-help");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "golang-1.13.3-10.h40.eulerosv2r9",
  "golang-devel-1.13.3-10.h40.eulerosv2r9",
  "golang-help-1.13.3-10.h40.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "golang");
}
