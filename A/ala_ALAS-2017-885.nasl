#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-885.
#

include("compat.inc");

if (description)
{
  script_id(102873);
  script_version("3.5");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-7546", "CVE-2017-7547", "CVE-2017-7548");
  script_xref(name:"ALAS", value:"2017-885");

  script_name(english:"Amazon Linux AMI : postgresql94 / postgresql95 (ALAS-2017-885)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"pg_user_mappings view discloses passwords to users lacking server
privileges :

An authorization flaw was found in the way PostgreSQL handled access
to the pg_user_mappings view on foreign servers. A remote
authenticated attacker could potentially use this flaw to retrieve
passwords from the user mappings defined by the foreign server owners
without actually having the privileges to do so. (CVE-2017-7547)

Empty password accepted in some authentication methods :

It was found that authenticating to a PostgreSQL database account with
an empty password was possible despite libpq's refusal to send an
empty password. A remote attacker could potentially use this flaw to
gain access to database accounts with empty passwords. (CVE-2017-7546)

lo_put() function ignores ACLs :

An authorization flaw was found in the way PostgreSQL handled large
objects. A remote authenticated attacker with no privileges on a large
object could potentially use this flaw to overwrite the entire content
of the object, thus resulting in denial of service. (CVE-2017-7548)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-885.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update postgresql94' to update your system.

Run 'yum update postgresql95' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql94-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-plpython26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-plpython27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:postgresql95-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");
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
if (rpm_check(release:"ALA", reference:"postgresql94-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-contrib-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-debuginfo-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-devel-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-docs-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-libs-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-plperl-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-plpython26-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-plpython27-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-server-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql94-test-9.4.13-1.69.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-contrib-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-debuginfo-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-devel-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-docs-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-libs-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-plperl-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-plpython26-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-plpython27-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-server-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-static-9.5.8-1.73.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"postgresql95-test-9.5.8-1.73.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql94 / postgresql94-contrib / postgresql94-debuginfo / etc");
}
