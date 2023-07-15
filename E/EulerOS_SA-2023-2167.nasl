#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176997);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/09");

  script_cve_id("CVE-2023-23934", "CVE-2023-25577");

  script_name(english:"EulerOS 2.0 SP5 : python-werkzeug (EulerOS-SA-2023-2167)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python-werkzeug package installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

  - Werkzeug is a comprehensive WSGI web application library. Browsers may allow 'nameless' cookies that look
    like `=value` instead of `key=value`. A vulnerable browser may allow a compromised application on an
    adjacent subdomain to exploit this to set a cookie like `=__Host-test=bad` for another subdomain. Werkzeug
    prior to 2.2.3 will parse the cookie `=__Host-test=bad` as __Host-test=bad`. If a Werkzeug application is
    running next to a vulnerable or malicious subdomain which sets such a cookie using a vulnerable browser,
    the Werkzeug application will see the bad cookie value but the valid cookie key. The issue is fixed in
    Werkzeug 2.2.3. (CVE-2023-23934)

  - Werkzeug is a comprehensive WSGI web application library. Prior to version 2.2.3, Werkzeug's multipart
    form data parser will parse an unlimited number of parts, including file parts. Parts can be a small
    amount of bytes, but each requires CPU time to parse and may use more memory as Python data. If a request
    can be made to an endpoint that accesses `request.data`, `request.form`, `request.files`, or
    `request.get_data(parse_form_data=False)`, it can cause unexpectedly high resource usage. This allows an
    attacker to cause a denial of service by sending crafted multipart data to an endpoint that will parse it.
    The amount of CPU time required can block worker processes from handling legitimate requests. The amount
    of RAM required can trigger an out of memory kill of the process. Unlimited file parts can use up memory
    and file handles. If many concurrent requests are sent continuously, this can exhaust or kill all
    available workers. Version 2.2.3 contains a patch for this issue. (CVE-2023-25577)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2167
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8335d531");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-werkzeug packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23934");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-werkzeug");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

var flag = 0;

var pkgs = [
  "python-werkzeug-0.9.1-2.h2.eulerosv2r7"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-werkzeug");
}
