#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-864.
#

include("compat.inc");

if (description)
{
  script_id(102179);
  script_version("3.2");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2016-6129");
  script_xref(name:"ALAS", value:"2017-864");

  script_name(english:"Amazon Linux AMI : libtommath / libtomcrypt (ALAS-2017-864)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"possible OP-TEE Bleichenbacher attack :

The rsa_verify_hash_ex function in rsa_verify_hash.c in LibTomCrypt,
as used in OP-TEE before 2.2.0, does not validate that the message
length is equal to the ASN.1 encoded data length, which makes it
easier for remote attackers to forge RSA signatures or public
certificates by leveraging a Bleichenbacher signature forgery attack.
(CVE-2016-6129)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-864.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update libtommath' to update your system.

Run 'yum update libtomcrypt' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtomcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtomcrypt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtomcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtommath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtommath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libtommath-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"libtomcrypt-1.17-25.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtomcrypt-debuginfo-1.17-25.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtomcrypt-devel-1.17-25.4.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtommath-0.42.0-5.3.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtommath-debuginfo-0.42.0-5.3.3.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libtommath-devel-0.42.0-5.3.3.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtomcrypt / libtomcrypt-debuginfo / libtomcrypt-devel / etc");
}
