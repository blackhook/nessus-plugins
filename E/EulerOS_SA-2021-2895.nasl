#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156517);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/06");

  script_cve_id(
    "CVE-2020-25709",
    "CVE-2020-25710",
    "CVE-2020-36221",
    "CVE-2020-36222",
    "CVE-2020-36223",
    "CVE-2020-36224",
    "CVE-2020-36225",
    "CVE-2020-36226",
    "CVE-2020-36227",
    "CVE-2020-36228",
    "CVE-2020-36229",
    "CVE-2020-36230",
    "CVE-2021-27212"
  );
  script_xref(name:"IAVB", value:"2021-B-0014");

  script_name(english:"EulerOS Virtualization 3.0.2.6 : openldap (EulerOS-SA-2021-2895)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openldap packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - A flaw was found in OpenLDAP. This flaw allows an attacker who can send a malicious packet to be processed
    by OpenLDAP's slapd server, to trigger an assertion failure. The highest threat from this vulnerability is
    to system availability. (CVE-2020-25709)

  - A flaw was found in OpenLDAP in versions before 2.4.56. This flaw allows an attacker who sends a malicious
    packet processed by OpenLDAP to force a failed assertion in csnNormalize23(). The highest threat from this
    vulnerability is to system availability. (CVE-2020-25710)

  - An integer underflow was discovered in OpenLDAP before 2.4.57 leading to slapd crashes in the Certificate
    Exact Assertion processing, resulting in denial of service (schema_init.c serialNumberAndIssuerCheck).
    (CVE-2020-36221)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to an assertion failure in slapd in the
    saslAuthzTo validation, resulting in denial of service. (CVE-2020-36222)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to a slapd crash in the Values Return Filter
    control handling, resulting in denial of service (double free and out-of-bounds read). (CVE-2020-36223)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to an invalid pointer free and slapd crash in the
    saslAuthzTo processing, resulting in denial of service. (CVE-2020-36224)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to a double free and slapd crash in the
    saslAuthzTo processing, resulting in denial of service. (CVE-2020-36225)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to a memch->bv_len miscalculation and slapd crash
    in the saslAuthzTo processing, resulting in denial of service. (CVE-2020-36226)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading to an infinite loop in slapd with the cancel_extop
    Cancel operation, resulting in denial of service. (CVE-2020-36227)

  - An integer underflow was discovered in OpenLDAP before 2.4.57 leading to a slapd crash in the Certificate
    List Exact Assertion processing, resulting in denial of service. (CVE-2020-36228)

  - A flaw was discovered in ldap_X509dn2bv in OpenLDAP before 2.4.57 leading to a slapd crash in the X.509 DN
    parsing in ad_keystring, resulting in denial of service. (CVE-2020-36229)

  - A flaw was discovered in OpenLDAP before 2.4.57 leading in an assertion failure in slapd in the X.509 DN
    parsing in decode.c ber_next_element, resulting in denial of service. (CVE-2020-36230)

  - In OpenLDAP through 2.4.57 and 2.5.x through 2.5.1alpha, an assertion failure in slapd can occur in the
    issuerAndThisUpdateCheck function via a crafted packet, resulting in a denial of service (daemon exit) via
    a short timestamp. This is related to schema_init.c and checkTime. (CVE-2021-27212)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2895
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b426beaf");
  script_set_attribute(attribute:"solution", value:
"Update the affected openldap packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27212");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openldap-clients");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.6");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "openldap-2.4.44-15.h16.eulerosv2r7",
  "openldap-clients-2.4.44-15.h16.eulerosv2r7"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openldap");
}
