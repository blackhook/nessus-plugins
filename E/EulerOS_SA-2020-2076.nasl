#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140843);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/13");

  script_cve_id(
    "CVE-2015-0204",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-1790"
  );
  script_bugtraq_id(
    71936,
    73196,
    73231,
    73237,
    75157
  );

  script_name(english:"EulerOS 2.0 SP3 : openssl098e (EulerOS-SA-2020-2076)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl098e package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The PKCS7_dataDecodefunction in crypto/pkcs7/pk7_doit.c
    in OpenSSL before 0.9.8zg, 1.0.0 before 1.0.0s, 1.0.1
    before 1.0.1n, and 1.0.2 before 1.0.2b allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via a PKCS#7 blob
    that uses ASN.1 encoding and lacks inner
    EncryptedContent data.(CVE-2015-1790)

  - The PKCS#7 implementation in OpenSSL before 0.9.8zf,
    1.0.0 before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2
    before 1.0.2a does not properly handle a lack of outer
    ContentInfo, which allows attackers to cause a denial
    of service (NULL pointer dereference and application
    crash) by leveraging an application that processes
    arbitrary PKCS#7 data and providing malformed data with
    ASN.1 encoding, related to crypto/pkcs7/pk7_doit.c and
    crypto/pkcs7/pk7_lib.c.(CVE-2015-0289)

  - The X509_to_X509_REQ function in crypto/x509/x509_req.c
    in OpenSSL before 0.9.8zf, 1.0.0 before 1.0.0r, 1.0.1
    before 1.0.1m, and 1.0.2 before 1.0.2a might allow
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via an invalid
    certificate key.(CVE-2015-0288)

  - The ssl3_get_key_exchange function in s3_clnt.c in
    OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1
    before 1.0.1k allows remote SSL servers to conduct
    RSA-to-EXPORT_RSA downgrade attacks and facilitate
    brute-force decryption by offering a weak ephemeral RSA
    key in a noncompliant role, related to the 'FREAK'
    issue. NOTE: the scope of this CVE is only client code
    based on OpenSSL, not EXPORT_RSA issues associated with
    servers or other TLS implementations.(CVE-2015-0204)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2076
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b5a8bdb");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl098e packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-1790");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl098e");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssl098e-0.9.8e-29.3.h9"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl098e");
}
