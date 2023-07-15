#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1302.
#

include("compat.inc");

if (description)
{
  script_id(129560);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/23");

  script_cve_id("CVE-2017-10684", "CVE-2017-10685", "CVE-2017-11112", "CVE-2017-11113");
  script_xref(name:"ALAS", value:"2019-1302");

  script_name(english:"Amazon Linux 2 : ncurses (ALAS-2019-1302)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In ncurses 6.0, there is an attempted 0xffffffffffffffff access in the
append_acs function of tinfo/parse_entry.c. It could lead to a remote
denial of service attack if the terminfo library code is used to
process untrusted terminfo data. (CVE-2017-11112)

In ncurses 6.0, there is a NULL pointer Dereference in the
_nc_parse_entry function of tinfo/parse_entry.c. It could lead to a
remote denial of service attack if the terminfo library code is used
to process untrusted terminfo data. (CVE-2017-11113)

In ncurses 6.0, there is a stack-based buffer overflow in the
fmt_entry function. A crafted input will lead to a remote arbitrary
code execution attack. (CVE-2017-10684)

In ncurses 6.0, there is a format string vulnerability in the
fmt_entry function. A crafted input will lead to a remote arbitrary
code execution attack. (CVE-2017-10685)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1302.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ncurses' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ncurses-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ncurses-c++-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ncurses-compat-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ncurses-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ncurses-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ncurses-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ncurses-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ncurses-term");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"ncurses-6.0-8.20170212.amzn2.1.3")) flag++;
if (rpm_check(release:"AL2", reference:"ncurses-base-6.0-8.20170212.amzn2.1.3")) flag++;
if (rpm_check(release:"AL2", reference:"ncurses-c++-libs-6.0-8.20170212.amzn2.1.3")) flag++;
if (rpm_check(release:"AL2", reference:"ncurses-compat-libs-6.0-8.20170212.amzn2.1.3")) flag++;
if (rpm_check(release:"AL2", reference:"ncurses-debuginfo-6.0-8.20170212.amzn2.1.3")) flag++;
if (rpm_check(release:"AL2", reference:"ncurses-devel-6.0-8.20170212.amzn2.1.3")) flag++;
if (rpm_check(release:"AL2", reference:"ncurses-libs-6.0-8.20170212.amzn2.1.3")) flag++;
if (rpm_check(release:"AL2", reference:"ncurses-static-6.0-8.20170212.amzn2.1.3")) flag++;
if (rpm_check(release:"AL2", reference:"ncurses-term-6.0-8.20170212.amzn2.1.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ncurses / ncurses-base / ncurses-c++-libs / ncurses-compat-libs / etc");
}
