#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-546.
#

include("compat.inc");

if (description)
{
  script_id(84247);
  script_version("2.5");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2015-3165");
  script_xref(name:"ALAS", value:"2015-546");

  script_name(english:"Amazon Linux AMI : postgresql93 (ALAS-2015-546)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Double free vulnerability in PostgreSQL before 9.0.20, 9.1.x before
9.1.16, 9.2.x before 9.2.11, 9.3.x before 9.3.7, and 9.4.x before
9.4.2 allows remote attackers to cause a denial of service (crash) by
closing an SSL session at a time when the authentication timeout will
expire during the session shutdown sequence."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-546.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update postgresql93' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql93-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/18");
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
if (rpm_check(release:"ALA", reference:"postgresql93-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-contrib-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-debuginfo-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-devel-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-docs-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-libs-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-plperl-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-plpython26-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-plpython27-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-pltcl-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-server-9.3.9-1.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql93-test-9.3.9-1.58.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql93 / postgresql93-contrib / postgresql93-debuginfo / etc");
}
