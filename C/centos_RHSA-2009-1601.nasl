#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1601 and 
# CentOS Errata and Security Advisory 2009:1601 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67077);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2009-0689");
  script_bugtraq_id(35510);
  script_xref(name:"RHSA", value:"2009:1601");

  script_name(english:"CentOS 4 / 5 : kdelibs (CESA-2009:1601)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The kdelibs packages provide libraries for the K Desktop Environment
(KDE).

A buffer overflow flaw was found in the kdelibs string to floating
point conversion routines. A web page containing malicious JavaScript
could crash Konqueror or, potentially, execute arbitrary code with the
privileges of the user running Konqueror. (CVE-2009-0689)

Users should upgrade to these updated packages, which contain a
backported patch to correct this issue. The desktop must be restarted
(log out, then log back in) for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-November/016334.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e28620f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-November/016335.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02fff55d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-November/016336.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26b0881e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-November/016337.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66d0b7b4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kdelibs-3.3.1-17.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kdelibs-3.3.1-17.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"kdelibs-devel-3.3.1-17.el4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"kdelibs-devel-3.3.1-17.el4.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"kdelibs-3.5.4-25.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kdelibs-apidocs-3.5.4-25.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"kdelibs-devel-3.5.4-25.el5.centos.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-apidocs / kdelibs-devel");
}
