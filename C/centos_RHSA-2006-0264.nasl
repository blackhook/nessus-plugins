#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0264 and 
# CentOS Errata and Security Advisory 2006:0264 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21893);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-0058");
  script_xref(name:"RHSA", value:"2006:0264");

  script_name(english:"CentOS 3 / 4 : sendmail (CESA-2006:0264)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sendmail packages to fix a security issue are now available
for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Sendmail is a Mail Transport Agent (MTA) used to send mail between
machines.

A flaw in the handling of asynchronous signals was discovered in
Sendmail. A remote attacker may be able to exploit a race condition to
execute arbitrary code as root. The Common Vulnerabilities and
Exposures project assigned the name CVE-2006-0058 to this issue.

By default on Red Hat Enterprise Linux 3 and 4, Sendmail is configured
to only accept connections from the local host. Therefore, only users
who have configured Sendmail to listen to remote hosts would be able
to be remotely exploited by this vulnerability.

Users of Sendmail are advised to upgrade to these erratum packages,
which contain a backported patch from the Sendmail team to correct
this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012768.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7f1bc55"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012769.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa493fd6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012771.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d121fba"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012773.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97fca209"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012775.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ffe36921"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-March/012776.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e36fe661"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sendmail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail-cf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"sendmail-8.12.11-4.RHEL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"sendmail-cf-8.12.11-4.RHEL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"sendmail-devel-8.12.11-4.RHEL3.4")) flag++;
if (rpm_check(release:"CentOS-3", reference:"sendmail-doc-8.12.11-4.RHEL3.4")) flag++;

if (rpm_check(release:"CentOS-4", reference:"sendmail-8.13.1-3.RHEL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"sendmail-cf-8.13.1-3.RHEL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"sendmail-devel-8.13.1-3.RHEL4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"sendmail-doc-8.13.1-3.RHEL4.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sendmail / sendmail-cf / sendmail-devel / sendmail-doc");
}
