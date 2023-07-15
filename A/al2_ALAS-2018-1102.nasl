#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1102.
#

include("compat.inc");

if (description)
{
  script_id(118833);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/14");

  script_cve_id("CVE-2017-3735", "CVE-2018-0495", "CVE-2018-0732", "CVE-2018-0739");
  script_xref(name:"ALAS", value:"2018-1102");

  script_name(english:"Amazon Linux 2 : openssl (ALAS-2018-1102)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"During key agreement in a TLS handshake using a DH(E) based
ciphersuite a malicious server can send a very large prime value to
the client. This will cause the client to spend an unreasonably long
period of time generating a key for this prime resulting in a hang
until the client has finished. This could be exploited in a Denial Of
Service attack.(CVE-2018-0732)

Libgcrypt before 1.7.10 and 1.8.x before 1.8.3 allows a memory-cache
side-channel attack on ECDSA signatures that can be mitigated through
the use of blinding during the signing process in the
_gcry_ecc_ecdsa_sign function in cipher/ecc-ecdsa.c, aka the Return Of
the Hidden Number Problem or ROHNP. To discover an ECDSA key, the
attacker needs access to either the local machine or a different
virtual machine on the same physical host.(CVE-2018-0495)

Constructed ASN.1 types with a recursive definition (such as can be
found in PKCS7) could eventually exceed the stack given malicious
input with excessive recursion. This could result in a Denial Of
Service attack. There are no such structures used within SSL/TLS that
come from untrusted sources so this is considered safe.(CVE-2018-0739)

While parsing an IPAddressFamily extension in an X.509 certificate, it
is possible to do a one-byte overread. This would result in an
incorrect text display of the certificate. This bug has been present
since 2006.(CVE-2017-3735)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1102.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update openssl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3735");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"openssl-1.0.2k-16.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-debuginfo-1.0.2k-16.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-devel-1.0.2k-16.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-libs-1.0.2k-16.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-perl-1.0.2k-16.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-static-1.0.2k-16.amzn2.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-libs / etc");
}
