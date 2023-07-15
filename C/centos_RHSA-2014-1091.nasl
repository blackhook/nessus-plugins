#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1091 and 
# CentOS Errata and Security Advisory 2014:1091 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77384);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-0240");
  script_xref(name:"RHSA", value:"2014:1091");

  script_name(english:"CentOS 7 : mod_wsgi (CESA-2014:1091)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated mod_wsgi package that fixes one security issue is now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The mod_wsgi adapter is an Apache module that provides a
WSGI-compliant interface for hosting Python-based web applications
within Apache.

It was found that mod_wsgi did not properly drop privileges if the
call to setuid() failed. If mod_wsgi was set up to allow unprivileged
users to run WSGI applications, a local user able to run a WSGI
application could possibly use this flaw to escalate their privileges
on the system. (CVE-2014-0240)

Note: mod_wsgi is not intended to provide privilege separation for
WSGI applications. Systems relying on mod_wsgi to limit or sandbox the
privileges of mod_wsgi applications should migrate to a different
solution with proper privilege separation.

Red Hat would like to thank Graham Dumpleton for reporting this issue.
Upstream acknowledges Robert Kisteleki as the original reporter.

All mod_wsgi users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2014-August/020506.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af852d27"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mod_wsgi package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0240");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"mod_wsgi-3.4-12.el7_0")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_wsgi");
}
