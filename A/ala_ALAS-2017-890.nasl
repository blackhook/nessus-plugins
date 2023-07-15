#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-890.
#

include('compat.inc');

if (description)
{
  script_id(103224);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-1000061");
  script_xref(name:"ALAS", value:"2017-890");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Amazon Linux AMI : xmlsec1 (ALAS-2017-890)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It was discovered xmlsec1's use of libxml2 inadvertently enabled
external entity expansion (XXE) along with validation. An attacker
could craft an XML file that would cause xmlsec1 to try and read local
files or HTTP/FTP URLs, leading to information disclosure or denial of
service. (CVE-2017-1000061)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2017-890.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update xmlsec1' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1-gcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1-gcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1-gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xmlsec1-openssl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

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
if (rpm_check(release:"ALA", reference:"xmlsec1-1.2.20-7.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xmlsec1-debuginfo-1.2.20-7.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xmlsec1-devel-1.2.20-7.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xmlsec1-gcrypt-1.2.20-7.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xmlsec1-gcrypt-devel-1.2.20-7.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xmlsec1-gnutls-1.2.20-7.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xmlsec1-gnutls-devel-1.2.20-7.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xmlsec1-nss-1.2.20-7.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xmlsec1-nss-devel-1.2.20-7.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xmlsec1-openssl-1.2.20-7.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xmlsec1-openssl-devel-1.2.20-7.4.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xmlsec1 / xmlsec1-debuginfo / xmlsec1-devel / xmlsec1-gcrypt / etc");
}
