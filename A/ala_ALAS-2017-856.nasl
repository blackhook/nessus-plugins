#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-856.
#

include("compat.inc");

if (description)
{
  script_id(101273);
  script_version("3.5");
  script_cvs_date("Date: 2019/04/10 16:10:16");

  script_cve_id("CVE-2017-9462");
  script_xref(name:"ALAS", value:"2017-856");

  script_name(english:"Amazon Linux AMI : mercurial (ALAS-2017-856)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Python debugger accessible to authorized users :

A flaw was found in the way 'hg serve --stdio' command in Mercurial
handled command-line options. A remote, authenticated attacker could
use this flaw to execute arbitrary code on the Mercurial server by
using specially crafted command-line options. (CVE-2017-9462)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-856.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mercurial' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mercurial Custom hg-ssh Wrapper Remote Code Exec');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-mercurial-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mercurial-python27");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"emacs-mercurial-3.7.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"emacs-mercurial-el-3.7.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-common-3.7.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-debuginfo-3.7.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-python26-3.7.3-1.28.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mercurial-python27-3.7.3-1.28.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-mercurial / emacs-mercurial-el / mercurial-common / etc");
}
