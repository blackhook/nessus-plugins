#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0967 and 
# CentOS Errata and Security Advisory 2008:0967 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(37062);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-2364", "CVE-2008-2939");
  script_bugtraq_id(29653, 30560);
  script_xref(name:"RHSA", value:"2008:0967");

  script_name(english:"CentOS 3 / 4 / 5 : httpd (CESA-2008:0967)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that resolve several security issues and fix a
bug are now available for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

A flaw was found in the mod_proxy Apache module. An attacker in
control of a Web server to which requests were being proxied could
have caused a limited denial of service due to CPU consumption and
stack exhaustion. (CVE-2008-2364)

A flaw was found in the mod_proxy_ftp Apache module. If Apache was
configured to support FTP-over-HTTP proxying, a remote attacker could
have performed a cross-site scripting attack. (CVE-2008-2939)

In addition, these updated packages fix a bug found in the handling of
the 'ProxyRemoteMatch' directive in the Red Hat Enterprise Linux 4
httpd packages. This bug is not present in the Red Hat Enterprise
Linux 3 or Red Hat Enterprise Linux 5 packages.

Users of httpd should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015395.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf4faef4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015396.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5584c31"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015399.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5c64772"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015400.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?300b95f6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015404.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b4b12b1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015410.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac57a22a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?01627d34"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-November/015418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dcfed5a6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"httpd-2.0.46-71.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", reference:"httpd-devel-2.0.46-71.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mod_ssl-2.0.46-71.ent.centos")) flag++;

if (rpm_check(release:"CentOS-4", reference:"httpd-2.0.52-41.ent.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-devel-2.0.52-41.ent.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-manual-2.0.52-41.ent.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-suexec-2.0.52-41.ent.2.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mod_ssl-2.0.52-41.ent.2.centos4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"httpd-2.2.3-11.el5_2.centos.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-devel-2.2.3-11.el5_2.centos.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"httpd-manual-2.2.3-11.el5_2.centos.4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"mod_ssl-2.2.3-11.el5_2.centos.4")) flag++;


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
