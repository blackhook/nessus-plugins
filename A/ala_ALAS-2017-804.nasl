#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-804.
#

include("compat.inc");

if (description)
{
  script_id(97556);
  script_version("3.2");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2016-9963");
  script_xref(name:"ALAS", value:"2017-804");

  script_name(english:"Amazon Linux AMI : exim (ALAS-2017-804)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that Exim leaked DKIM signing private keys to the
'mainlog' log file. As a result, an attacker with access to system log
files could potentially access these leaked DKIM private keys."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-804.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update exim' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-greylist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exim-pgsql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");
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
if (rpm_check(release:"ALA", reference:"exim-4.88-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"exim-debuginfo-4.88-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"exim-greylist-4.88-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"exim-mon-4.88-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"exim-mysql-4.88-2.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"exim-pgsql-4.88-2.11.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exim / exim-debuginfo / exim-greylist / exim-mon / exim-mysql / etc");
}
