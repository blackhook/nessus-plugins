#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176998);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/09");

  script_cve_id("CVE-2023-0464", "CVE-2023-0465", "CVE-2023-0466");

  script_name(english:"EulerOS 2.0 SP8 : compat-openssl10 (EulerOS-SA-2023-2187)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the compat-openssl10 package installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

  - A security vulnerability has been identified in all supported versions of OpenSSL related to the
    verification of X.509 certificate chains that include policy constraints. Attackers may be able to exploit
    this vulnerability by creating a malicious certificate chain that triggers exponential use of
    computational resources, leading to a denial-of-service (DoS) attack on affected systems. Policy
    processing is disabled by default but can be enabled by passing the `-policy' argument to the command line
    utilities or by calling the `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0464)

  - Applications that use a non-default option when verifying certificates may be vulnerable to an attack from
    a malicious CA to circumvent certain checks. Invalid certificate policies in leaf certificates are
    silently ignored by OpenSSL and other certificate policy checks are skipped for that certificate. A
    malicious CA could use this to deliberately assert invalid certificate policies in order to circumvent
    policy checking on the certificate altogether. Policy processing is disabled by default but can be enabled
    by passing the `-policy' argument to the command line utilities or by calling the
    `X509_VERIFY_PARAM_set1_policies()' function. (CVE-2023-0465)

  - The function X509_VERIFY_PARAM_add0_policy() is documented to implicitly enable the certificate policy
    check when doing certificate verification. However the implementation of the function does not enable the
    check which allows certificates with invalid or incorrect policies to pass the certificate verification.
    As suddenly enabling the policy check could break existing deployments it was decided to keep the existing
    behavior of the X509_VERIFY_PARAM_add0_policy() function. Instead the applications that require OpenSSL to
    perform certificate policy check need to use X509_VERIFY_PARAM_set1_policies() or explicitly enable the
    policy check by calling X509_VERIFY_PARAM_set_flags() with the X509_V_FLAG_POLICY_CHECK flag argument.
    Certificate policy checks are disabled by default in OpenSSL and are not commonly used by applications.
    (CVE-2023-0466)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2187
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1313bbbc");
  script_set_attribute(attribute:"solution", value:
"Update the affected compat-openssl10 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:compat-openssl10");
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
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "compat-openssl10-1.0.2o-3.h18.eulerosv2r8"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "compat-openssl10");
}
