#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-413.
#

include("compat.inc");

if (description)
{
  script_id(78356);
  script_version("1.3");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2014-3522");
  script_xref(name:"ALAS", value:"2014-413");

  script_name(english:"Amazon Linux AMI : subversion (ALAS-2014-413)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Serf RA layer in Apache Subversion 1.4.0 through 1.7.x before
1.7.18 and 1.8.x before 1.8.10 does not properly handle wildcards in
the Common Name (CN) or subjectAltName field of the X.509 certificate,
which allows man-in-the-middle attackers to spoof servers via a
crafted certificate."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-413.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update subversion' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"mod_dav_svn-1.8.10-1.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-1.8.10-1.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-debuginfo-1.8.10-1.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-devel-1.8.10-1.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-javahl-1.8.10-1.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-libs-1.8.10-1.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-perl-1.8.10-1.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-python-1.8.10-1.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-ruby-1.8.10-1.44.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"subversion-tools-1.8.10-1.44.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-debuginfo / subversion-devel / etc");
}
