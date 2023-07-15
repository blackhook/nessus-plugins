#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-929.
#

include("compat.inc");

if (description)
{
  script_id(105053);
  script_version("3.3");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-12618");
  script_xref(name:"ALAS", value:"2017-929");

  script_name(english:"Amazon Linux AMI : apr-util (ALAS-2017-929)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache Portable Runtime Utility (APR-util) fails to validate the
integrity of SDBM database files used by apr_sdbm*() functions,
resulting in a possible out of bound read access. A local user with
write access to the database can make a program or process using these
functions crash, and cause a denial of service.(CVE-2017-12618)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-929.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update apr-util' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util-freetds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:apr-util-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/07");
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
if (rpm_check(release:"ALA", reference:"apr-util-1.5.4-6.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apr-util-debuginfo-1.5.4-6.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apr-util-devel-1.5.4-6.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apr-util-freetds-1.5.4-6.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apr-util-ldap-1.5.4-6.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apr-util-mysql-1.5.4-6.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apr-util-nss-1.5.4-6.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apr-util-odbc-1.5.4-6.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apr-util-openssl-1.5.4-6.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apr-util-pgsql-1.5.4-6.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"apr-util-sqlite-1.5.4-6.18.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apr-util / apr-util-debuginfo / apr-util-devel / apr-util-freetds / etc");
}
