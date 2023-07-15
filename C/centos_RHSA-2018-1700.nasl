#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1700 and 
# CentOS Errata and Security Advisory 2018:1700 respectively.
#

include("compat.inc");

if (description)
{
  script_id(110204);
  script_version("1.9");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-1124", "CVE-2018-1126");
  script_xref(name:"RHSA", value:"2018:1700");
  script_xref(name:"IAVA", value:"2018-A-0174");

  script_name(english:"CentOS 7 : procps-ng (CESA-2018:1700)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for procps-ng is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The procps-ng packages contain a set of system utilities that provide
system information, including ps, free, skill, pkill, pgrep, snice,
tload, top, uptime, vmstat, w, watch, and pwdx.

Security Fix(es) :

* procps-ng, procps: Integer overflows leading to heap overflow in
file2strvec (CVE-2018-1124)

* procps-ng, procps: incorrect integer size in proc/alloc.* leading to
truncation / integer overflow issues (CVE-2018-1126)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Qualys Research Labs for reporting these
issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-May/022847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0be8f3b6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected procps-ng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1126");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:procps-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:procps-ng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:procps-ng-i18n");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"procps-ng-3.3.10-17.el7_5.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"procps-ng-devel-3.3.10-17.el7_5.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"procps-ng-i18n-3.3.10-17.el7_5.2")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "procps-ng / procps-ng-devel / procps-ng-i18n");
}
