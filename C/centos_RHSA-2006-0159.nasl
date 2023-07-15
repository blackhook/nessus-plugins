#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0159 and 
# CentOS Errata and Security Advisory 2006:0159 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21884);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2970", "CVE-2005-3352", "CVE-2005-3357");
  script_bugtraq_id(15834, 16152);
  script_xref(name:"RHSA", value:"2006:0159");

  script_name(english:"CentOS 3 / 4 : httpd (CESA-2006:0159)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages that correct three security issues are
now available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular and freely-available Web server.

A memory leak in the worker MPM could allow remote attackers to cause
a denial of service (memory consumption) via aborted connections,
which prevents the memory for the transaction pool from being reused
for other connections. The Common Vulnerabilities and Exposures
project assigned the name CVE-2005-2970 to this issue. This
vulnerability only affects users who are using the non-default worker
MPM.

A flaw in mod_imap when using the Referer directive with image maps
was discovered. With certain site configurations, a remote attacker
could perform a cross-site scripting attack if a victim can be forced
to visit a malicious URL using certain web browsers. (CVE-2005-3352)

A NULL pointer dereference flaw in mod_ssl was discovered affecting
server configurations where an SSL virtual host is configured with
access control and a custom 400 error document. A remote attacker
could send a carefully crafted request to trigger this issue which
would lead to a crash. This crash would only be a denial of service if
using the non-default worker MPM. (CVE-2005-3357)

Users of httpd should update to these erratum packages which contain
backported patches to correct these issues along with some additional
bugs."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012537.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74987a03"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012538.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45a2e4c6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012540.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e02190f2"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012541.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?be8581ff"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012542.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4830549"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-January/012543.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?559e6b8d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/05");
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
if (rpm_check(release:"CentOS-3", reference:"httpd-2.0.46-56.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"httpd-devel-2.0.46-56.ent.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mod_ssl-2.0.46-56.ent.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"httpd-2.0.52-22.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-devel-2.0.52-22.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-manual-2.0.52-22.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-suexec-2.0.52-22.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mod_ssl-2.0.52-22.ent.centos4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-suexec / mod_ssl");
}
