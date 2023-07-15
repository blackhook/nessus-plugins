#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0844 and 
# CentOS Errata and Security Advisory 2011:0844 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(54938);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2011-0419", "CVE-2011-1928");
  script_bugtraq_id(47929);
  script_xref(name:"RHSA", value:"2011:0844");

  script_name(english:"CentOS 4 / 5 : apr (CESA-2011:0844)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated apr packages that fix one security issue are now available for
Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Apache Portable Runtime (APR) is a portability library used by the
Apache HTTP Server and other projects. It provides a free library of C
data structures and routines.

The fix for CVE-2011-0419 (released via RHSA-2011:0507) introduced an
infinite loop flaw in the apr_fnmatch() function when the
APR_FNM_PATHNAME matching flag was used. A remote attacker could
possibly use this flaw to cause a denial of service on an application
using the apr_fnmatch() function. (CVE-2011-1928)

Note: This problem affected httpd configurations using the 'Location'
directive with wildcard URLs. The denial of service could have been
triggered during normal operation; it did not specifically require a
malicious HTTP request.

This update also addresses additional problems introduced by the
rewrite of the apr_fnmatch() function, which was necessary to address
the CVE-2011-0419 flaw.

All apr users should upgrade to these updated packages, which contain
a backported patch to correct this issue. Applications using the apr
library, such as httpd, must be restarted for this update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-June/017607.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bcd8433"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-June/017608.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7612f342"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-May/017593.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?539b3068"
  );
  # https://lists.centos.org/pipermail/centos-announce/2011-May/017594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ae2d348"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected apr packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:apr-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"apr-0.9.4-26.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"apr-0.9.4-26.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"apr-devel-0.9.4-26.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"apr-devel-0.9.4-26.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"apr-1.2.7-11.el5_6.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-devel-1.2.7-11.el5_6.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"apr-docs-1.2.7-11.el5_6.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apr / apr-devel / apr-docs");
}
