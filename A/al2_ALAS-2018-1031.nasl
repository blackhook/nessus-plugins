#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1031.
#

include("compat.inc");

if (description)
{
  script_id(110448);
  script_version("1.5");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2018-1124", "CVE-2018-1126");
  script_xref(name:"ALAS", value:"2018-1031");
  script_xref(name:"IAVA", value:"2018-A-0174");

  script_name(english:"Amazon Linux 2 : procps-ng (ALAS-2018-1031)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple integer overflows leading to heap corruption flaws were
discovered in file2strvec(). These vulnerabilities can lead to
privilege escalation for a local attacker who can create entries in
procfs by starting processes, which will lead to crashes or arbitrary
code execution in proc utilities run by other users (eg pgrep, pkill,
pidof, w).(CVE-2018-1124)

A flaw was found where procps-ng provides wrappers for standard C
allocators that took `unsigned int` instead of `size_t` parameters. On
platforms where these differ (such as x86_64), this could cause
integer truncation, leading to undersized regions being returned to
callers that could then be overflowed. The only known exploitable
vector for this issue is CVE-2018-1124 .(CVE-2018-1126)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1031.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update procps-ng' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:procps-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:procps-ng-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:procps-ng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:procps-ng-i18n");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"procps-ng-3.3.10-17.amzn2.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"procps-ng-debuginfo-3.3.10-17.amzn2.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"procps-ng-devel-3.3.10-17.amzn2.2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"procps-ng-i18n-3.3.10-17.amzn2.2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "procps-ng / procps-ng-debuginfo / procps-ng-devel / procps-ng-i18n");
}
