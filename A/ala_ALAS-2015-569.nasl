#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-569.
#

include('compat.inc');

if (description)
{
  script_id(84929);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2015-4000");
  script_xref(name:"ALAS", value:"2015-569");
  script_xref(name:"RHSA", value:"2015:1185");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Amazon Linux AMI : nss / nss-util (ALAS-2015-569) (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A flaw was found in the way the TLS protocol composes the
Diffie-Hellman (DH) key exchange. A man-in-the-middle attacker could
use this flaw to force the use of weak 512 bit export-grade keys
during the key exchange, allowing them do decrypt all traffic.
(CVE-2015-4000)

Please note that this update forces the TLS/SSL client implementation
in NSS to reject DH key sizes below 768 bits, which prevents sessions
to be downgraded to export-grade keys. Future updates may raise this
limit to 1024 bits.");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2015-569.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update nss nss-util' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

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
if (rpm_check(release:"ALA", reference:"nss-3.19.1-3.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-debuginfo-3.19.1-3.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-devel-3.19.1-3.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-pkcs11-devel-3.19.1-3.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-sysinit-3.19.1-3.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-tools-3.19.1-3.71.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-3.19.1-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-debuginfo-3.19.1-1.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nss-util-devel-3.19.1-1.41.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-sysinit / etc");
}
