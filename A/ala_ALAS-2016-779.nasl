#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-779.
#

include("compat.inc");

if (description)
{
  script_id(95935);
  script_version("3.2");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2016-1248");
  script_xref(name:"ALAS", value:"2016-779");

  script_name(english:"Amazon Linux AMI : vim (ALAS-2016-779)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was found in vim in how certain modeline options were
treated. An attacker could craft a file that, when opened in vim with
modelines enabled, could execute arbitrary commands with privileges of
the user running vim. (modelines are disabled by default for root, and
enabled by default for other users.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-779.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update vim' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"vim-common-8.0.0134-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"vim-debuginfo-8.0.0134-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"vim-enhanced-8.0.0134-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"vim-filesystem-8.0.0134-1.43.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"vim-minimal-8.0.0134-1.43.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vim-common / vim-debuginfo / vim-enhanced / vim-filesystem / etc");
}
