#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1362.
#

include("compat.inc");

if (description)
{
  script_id(131030);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2018-0734", "CVE-2019-1559");
  script_xref(name:"ALAS", value:"2019-1362");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Amazon Linux 2 : openssl (ALAS-2019-1362)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"If an application encounters a fatal protocol error and then calls
SSL_shutdown() twice (once to send a close_notify, and once to receive
one) then OpenSSL can respond differently to the calling application
if a 0 byte record is received with invalid padding compared to if a 0
byte record is received with an invalid MAC. If the application then
behaves differently based on that in a way that is detectable to the
remote peer, then this amounts to a padding oracle that could be used
to decrypt data. In order for this to be exploitable 'non-stitched'
ciphersuites must be in use. Stitched ciphersuites are optimised
implementations of certain commonly used ciphersuites. Also the
application must call SSL_shutdown() twice even if a protocol error
has occurred (applications should not do this but some do anyway).
Fixed in OpenSSL 1.0.2r (Affected 1.0.2-1.0.2q). (CVE-2019-1559)

The OpenSSL DSA signature algorithm has been shown to be vulnerable to
a timing side channel attack. An attacker could use variations in the
signing algorithm to recover the private key. Fixed in OpenSSL 1.1.1a
(Affected 1.1.1). Fixed in OpenSSL 1.1.0j (Affected 1.1.0-1.1.0i).
Fixed in OpenSSL 1.0.2q (Affected 1.0.2-1.0.2p). (CVE-2018-0734)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1362.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update openssl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"openssl-1.0.2k-19.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-debuginfo-1.0.2k-19.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-devel-1.0.2k-19.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-libs-1.0.2k-19.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-perl-1.0.2k-19.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-static-1.0.2k-19.amzn2.0.1")) flag++;

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
