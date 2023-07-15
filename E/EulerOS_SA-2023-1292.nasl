#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170790);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/30");

  script_cve_id(
    "CVE-2021-31799",
    "CVE-2021-31810",
    "CVE-2021-32066",
    "CVE-2021-41819",
    "CVE-2022-28739"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.2 : ruby (EulerOS-SA-2023-1292)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ruby packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - In RDoc 3.11 through 6.x before 6.3.1, as distributed with Ruby through 3.0.1, it is possible to execute
    arbitrary code via | and tags in a filename. (CVE-2021-31799)

  - An issue was discovered in Ruby through 2.6.7, 2.7.x through 2.7.3, and 3.x through 3.0.1. A malicious FTP
    server can use the PASV response to trick Net::FTP into connecting back to a given IP address and port.
    This potentially makes curl extract information about services that are otherwise private and not
    disclosed (e.g., the attacker can conduct port scans and service banner extractions). (CVE-2021-31810)

  - An issue was discovered in Ruby through 2.6.7, 2.7.x through 2.7.3, and 3.x through 3.0.1. Net::IMAP does
    not raise an exception when StartTLS fails with an an unknown response, which might allow man-in-the-
    middle attackers to bypass the TLS protections by leveraging a network position between the client and the
    registry to block the StartTLS command, aka a 'StartTLS stripping attack.' (CVE-2021-32066)

  - CGI::Cookie.parse in Ruby through 2.6.8 mishandles security prefixes in cookie names. This also affects
    the CGI gem through 0.3.0 for Ruby. (CVE-2021-41819)

  - There is a buffer over-read in Ruby before 2.6.10, 2.7.x before 2.7.6, 3.x before 3.0.4, and 3.1.x before
    3.1.2. It occurs in String-to-Float conversion, including Kernel#Float and String#to_f. (CVE-2022-28739)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1292
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33202f05");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32066");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28739");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:rubygems");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.2") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.2");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "ruby-2.0.0.648-33.h36.eulerosv2r7",
  "ruby-irb-2.0.0.648-33.h36.eulerosv2r7",
  "ruby-libs-2.0.0.648-33.h36.eulerosv2r7",
  "rubygem-bigdecimal-1.2.0-33.h36.eulerosv2r7",
  "rubygem-io-console-0.4.2-33.h36.eulerosv2r7",
  "rubygem-json-1.7.7-33.h36.eulerosv2r7",
  "rubygem-psych-2.0.0-33.h36.eulerosv2r7",
  "rubygem-rdoc-4.0.0-33.h36.eulerosv2r7",
  "rubygems-2.0.14.1-33.h36.eulerosv2r7"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
