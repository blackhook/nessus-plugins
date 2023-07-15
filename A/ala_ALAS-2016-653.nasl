#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-653.
#

include("compat.inc");

if (description)
{
  script_id(88756);
  script_version("2.13");
  script_cvs_date("Date: 2019/04/11 17:23:06");

  script_cve_id("CVE-2015-7547");
  script_xref(name:"ALAS", value:"2016-653");
  script_xref(name:"IAVA", value:"2016-A-0053");
  script_xref(name:"TRA", value:"TRA-2017-08");

  script_name(english:"Amazon Linux AMI : glibc (ALAS-2016-653)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A stack-based buffer overflow flaw was found in the send_dg() and
send_vc() functions, used by getaddrinfo() and other higher-level
interfaces of glibc. A remote attacker able to cause an application to
call either of these functions could use this flaw to execute
arbitrary code with the permissions of the user running the
application."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aws.amazon.com/amazon-linux-ami/faqs/#auto_update"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-653.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update glibc' to update your system. Note that you may need
to run 'yum clean all' first. Once this update has been applied,
'reboot your instance to ensure that all processes and daemons that
link against glibc are using the updated version'. On new instance
launches prior to Amazon Linux AMI 2015.09.2, you should still reboot
after cloud-init has automatically applied this update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"glibc-2.17-106.166.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-common-2.17-106.166.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-debuginfo-2.17-106.166.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-debuginfo-common-2.17-106.166.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-devel-2.17-106.166.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-headers-2.17-106.166.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-static-2.17-106.166.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"glibc-utils-2.17-106.166.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"nscd-2.17-106.166.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
}
