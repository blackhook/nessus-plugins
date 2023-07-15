#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-878.
#

include("compat.inc");

if (description)
{
  script_id(102866);
  script_version("3.2");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2016-0634", "CVE-2016-7543", "CVE-2016-9401");
  script_xref(name:"ALAS", value:"2017-878");

  script_name(english:"Amazon Linux AMI : bash (ALAS-2017-878)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"popd controlled free :

A denial of service flaw was found in the way bash handled popd
commands. A poorly written shell script could cause bash to crash
resulting in a local denial of service limited to a specific bash
session.(CVE-2016-9401)

Arbitrary code execution via malicious hostname :

An arbitrary command injection flaw was found in the way bash
processed the hostname value. A malicious DHCP server could use this
flaw to execute arbitrary commands on the DHCP client machines running
bash under specific circumstances.(CVE-2016-0634)

Specially crafted SHELLOPTS+PS4 variables allows command 
substitution :

An arbitrary command injection flaw was found in the way bash
processed the SHELLOPTS and PS4 environment variables. A local,
authenticated attacker could use this flaw to exploit poorly written
setuid programs to elevate their privileges under certain
circumstances. (CVE-2016-7543)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-878.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update bash' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bash-doc");
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
if (rpm_check(release:"ALA", reference:"bash-4.2.46-28.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bash-debuginfo-4.2.46-28.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bash-doc-4.2.46-28.37.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash / bash-debuginfo / bash-doc");
}
