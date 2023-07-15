#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128913);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-3571",
    "CVE-2015-0292",
    "CVE-2015-1789",
    "CVE-2015-3195",
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2108",
    "CVE-2016-2109",
    "CVE-2016-2177"
  );
  script_bugtraq_id(
    71937,
    73228,
    74107,
    75156,
    75769
  );

  script_name(english:"EulerOS 2.0 SP2 : openssl098e (EulerOS-SA-2019-1861)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl098e package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

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

  - A memory leak vulnerability was found in the way
    OpenSSL parsed PKCS#7 and CMS data. A remote attacker
    could use this flaw to cause an application that parses
    PKCS#7 or CMS data from untrusted sources to use an
    excessive amount of memory and possibly
    crash.(CVE-2015-3195)

  - OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1
    before 1.0.1k allows remote attackers to cause a denial
    of service (NULL pointer dereference and application
    crash) via a crafted DTLS message that is processed
    with a different read operation for the handshake
    header than for the handshake body, related to the
    dtls1_get_record function in d1_pkt.c and the
    ssl3_read_n function in s3_pkt.c.(CVE-2014-3571)

  - OpenSSL through 1.0.2h incorrectly uses pointer
    arithmetic for heap-buffer boundary checks, which might
    allow remote attackers to cause a denial of service
    (integer overflow and application crash) or possibly
    have unspecified other impact by leveraging unexpected
    malloc behavior, related to s3_srvr.c, ssl_sess.c, and
    t1_lib.c.(CVE-2016-2177)

  - An integer overflow flaw, leading to a buffer overflow,
    was found in the way the EVP_EncodeUpdate() function of
    OpenSSL parsed very large amounts of input data. A
    remote attacker could use this flaw to crash an
    application using OpenSSL or, possibly, execute
    arbitrary code with the permissions of the user running
    that application.(CVE-2016-2105)

  - An integer overflow flaw, leading to a buffer overflow,
    was found in the way the EVP_EncryptUpdate() function
    of OpenSSL parsed very large amounts of input data. A
    remote attacker could use this flaw to crash an
    application using OpenSSL or, possibly, execute
    arbitrary code with the permissions of the user running
    that application.(CVE-2016-2106)

  - A flaw was found in the way OpenSSL encoded certain
    ASN.1 data structures. An attacker could use this flaw
    to create a specially crafted certificate which, when
    verified or re-encoded by OpenSSL, could cause it to
    crash, or execute arbitrary code using the permissions
    of the user running an application compiled against the
    OpenSSL library.(CVE-2016-2108)

  - A denial of service flaw was found in the way OpenSSL
    parsed certain ASN.1-encoded data from BIO (OpenSSL's
    I/O abstraction) inputs. An application using OpenSSL
    that accepts untrusted ASN.1 BIO input could be forced
    to allocate an excessive amount of data.(CVE-2016-2109)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1861
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69e3dde9");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl098e packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/17");

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
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssl098e-0.9.8e-29.3.h6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
