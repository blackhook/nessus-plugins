#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129174);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/01");

  script_cve_id(
    "CVE-2015-0204",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0292",
    "CVE-2015-1789",
    "CVE-2015-1790"
  );
  script_bugtraq_id(
    71936,
    73196,
    73228,
    73231,
    73237,
    75156,
    75157
  );

  script_name(english:"EulerOS 2.0 SP5 : openssl098e (EulerOS-SA-2019-1980)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl098e package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - It was discovered that OpenSSL would accept ephemeral
    RSA keys when using non-export RSA cipher suites. A
    malicious server could make a TLS/SSL client using
    OpenSSL use a weaker key exchange
    method.(CVE-2015-0204)

  - A NULL pointer dereference flaw was found in OpenSSL's
    X.509 certificate handling implementation. A specially
    crafted X.509 certificate could cause an application
    using OpenSSL to crash if the application attempted to
    convert the certificate to a certificate
    request.(CVE-2015-0288)

  - A NULL pointer dereference was found in the way OpenSSL
    handled certain PKCS#7 inputs. An attacker able to make
    an application using OpenSSL verify, decrypt, or parse
    a specially crafted PKCS#7 input could cause that
    application to crash. TLS/SSL clients and servers using
    OpenSSL were not affected by this flaw.(CVE-2015-0289)

  - An integer underflow flaw, leading to a buffer
    overflow, was found in the way OpenSSL decoded
    malformed Base64-encoded inputs. An attacker able to
    make an application using OpenSSL decode a specially
    crafted Base64-encoded input (such as a PEM file) could
    use this flaw to cause the application to crash. Note:
    this flaw is not exploitable via the TLS/SSL protocol
    because the data being transferred is not
    Base64-encoded.(CVE-2015-0292)

  - An out-of-bounds read flaw was found in the
    X509_cmp_time() function of OpenSSL, which is used to
    test the expiry dates of SSL/TLS certificates. An
    attacker could possibly use a specially crafted SSL/TLS
    certificate or CRL (Certificate Revocation List), which
    when parsed by an application would cause that
    application to crash.(CVE-2015-1789)

  - A NULL pointer dereference was found in the way OpenSSL
    handled certain PKCS#7 inputs. An attacker able to make
    an application using OpenSSL verify, decrypt, or parse
    a specially crafted PKCS#7 input could cause that
    application to crash. TLS/SSL clients and servers using
    OpenSSL were not affected by this flaw.(CVE-2015-1790)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1980
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d2387ef");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl098e packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl098e");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssl098e-0.9.8e-29.3.h6.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl098e");
}
