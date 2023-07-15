#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-234.
#

include("compat.inc");

if (description)
{
  script_id(70896);
  script_version("1.4");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2013-4396");
  script_xref(name:"ALAS", value:"2013-234");
  script_xref(name:"RHSA", value:"2013:1426");

  script_name(english:"Amazon Linux AMI : xorg-x11-server (ALAS-2013-234)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A use-after-free flaw was found in the way the X.Org server handled
ImageText requests. A malicious, authorized client could use this flaw
to crash the X.Org server or, potentially, execute arbitrary code with
root privileges. (CVE-2013-4396)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-234.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update xorg-x11-server' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"xorg-x11-server-Xephyr-1.13.0-11.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-server-Xnest-1.13.0-11.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-server-Xvfb-1.13.0-11.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-server-common-1.13.0-11.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-server-debuginfo-1.13.0-11.18.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"xorg-x11-server-source-1.13.0-11.18.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xephyr / xorg-x11-server-Xnest / etc");
}
