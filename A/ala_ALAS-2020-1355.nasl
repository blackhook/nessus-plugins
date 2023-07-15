#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1355.
#

include("compat.inc");

if (description)
{
  script_id(134681);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/23");

  script_cve_id("CVE-2018-0495", "CVE-2018-12404", "CVE-2019-11729", "CVE-2019-11745");
  script_xref(name:"ALAS", value:"2020-1355");

  script_name(english:"Amazon Linux AMI : nss / nss-softokn,nss-util,nspr (ALAS-2020-1355)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow was found in the NSC_EncryptUpdate()
function in Mozilla nss. A remote attacker could trigger this flaw via
SRTP encrypt or decrypt operations, to execute arbitrary code with the
permissions of the user running the application (compiled with nss).
While the attack complexity is high, the impact to confidentiality,
integrity, and availability are high as well. (CVE-2019-11745)

A cached side channel attack during handshakes using RSA encryption
could allow for the decryption of encrypted content. This is a variant
of the Adaptive Chosen Ciphertext attack (AKA Bleichenbacher attack)
and affects all NSS versions prior to NSS 3.41. (CVE-2018-12404)

Empty or malformed p256-ECDH public keys may trigger a segmentation
fault due values being improperly sanitized before being copied into
memory and used. This vulnerability affects Firefox ESR < 60.8,
Firefox < 68, and Thunderbird < 60.8. (CVE-2019-11729 )

Libgcrypt before 1.7.10 and 1.8.x before 1.8.3 allows a memory-cache
side-channel attack on ECDSA signatures that can be mitigated through
the use of blinding during the signing process in the
_gcry_ecc_ecdsa_sign function in cipher/ecc-ecdsa.c, aka the Return Of
the Hidden Number Problem or ROHNP. To discover an ECDSA key, the
attacker needs access to either the local machine or a different
virtual machine on the same physical host. (CVE-2018-0495)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2020-1355.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update nss' to update your system.

Run 'yum update nss-softokn' to update your system.

Run 'yum update nss-util' to update your system.

Run 'yum update nspr' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"nspr-4.21.0-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nspr-debuginfo-4.21.0-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nspr-devel-4.21.0-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-3.44.0-7.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-debuginfo-3.44.0-7.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-devel-3.44.0-7.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-pkcs11-devel-3.44.0-7.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-softokn-3.44.0-8.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-softokn-debuginfo-3.44.0-8.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-softokn-devel-3.44.0-8.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-softokn-freebl-3.44.0-8.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-softokn-freebl-devel-3.44.0-8.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-sysinit-3.44.0-7.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-tools-3.44.0-7.84.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-3.44.0-4.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-debuginfo-3.44.0-4.56.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-devel-3.44.0-4.56.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-debuginfo / nspr-devel / nss / nss-debuginfo / etc");
}
