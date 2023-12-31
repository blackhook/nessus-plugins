#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-478.
#

include("compat.inc");

if (description)
{
  script_id(81324);
  script_version("1.3");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2015-0247");
  script_xref(name:"ALAS", value:"2015-478");

  script_name(english:"Amazon Linux AMI : e2fsprogs (ALAS-2015-478)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow flaw was found in e2fsprogs. A specially
crafted Ext2/3/4 file system could cause an application using the
ext2fs library (for example, fsck) to crash or, possibly, execute
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-478.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update e2fsprogs' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:e2fsprogs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:e2fsprogs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:e2fsprogs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:e2fsprogs-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcom_err");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcom_err-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"e2fsprogs-1.42.12-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"e2fsprogs-debuginfo-1.42.12-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"e2fsprogs-devel-1.42.12-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"e2fsprogs-libs-1.42.12-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"e2fsprogs-static-1.42.12-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcom_err-1.42.12-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcom_err-devel-1.42.12-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libss-1.42.12-1.34.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libss-devel-1.42.12-1.34.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "e2fsprogs / e2fsprogs-debuginfo / e2fsprogs-devel / e2fsprogs-libs / etc");
}
