#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0883 and 
# CentOS Errata and Security Advisory 2007:0883 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(26028);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-0242", "CVE-2007-4137");
  script_bugtraq_id(23269, 25657);
  script_xref(name:"RHSA", value:"2007:0883");

  script_name(english:"CentOS 3 / 4 / 5 : qt (CESA-2007:0883)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qt packages that correct two security flaws are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Qt is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System.

A flaw was found in the way Qt expanded certain UTF8 characters. It
was possible to prevent a Qt-based application from properly
sanitizing user-supplied input. This could, for example, result in a
cross-site scripting attack against the Konqueror web browser.
(CVE-2007-0242)

A buffer overflow flaw was found in the way Qt expanded malformed
Unicode strings. If an application linked against Qt parsed a
malicious Unicode string, it could lead to a denial of service or
possibly allow the execution of arbitrary code. (CVE-2007-4137)

Users of Qt should upgrade to these updated packages, which contain a
backported patch to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014190.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f79cf04"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014191.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfa694ad"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014192.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94ca4688"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014193.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb2cbee7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014194.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec2ad63b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014195.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdcf183a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014235.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60627ecc"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-September/014236.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?967ce360"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-MySQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-ODBC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-PostgreSQL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-designer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:qt-devel-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"qt-3.1.2-17.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-MySQL-3.1.2-17.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-ODBC-3.1.2-17.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-PostgreSQL-3.1.2-17.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-config-3.1.2-17.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-designer-3.1.2-17.RHEL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"qt-devel-3.1.2-17.RHEL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"qt-3.3.3-13.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-MySQL-3.3.3-13.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-ODBC-3.3.3-13.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-PostgreSQL-3.3.3-13.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-config-3.3.3-13.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-designer-3.3.3-13.RHEL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"qt-devel-3.3.3-13.RHEL4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"qt-3.3.6-23.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-MySQL-3.3.6-23.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-ODBC-3.3.6-23.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-PostgreSQL-3.3.6-23.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-config-3.3.6-23.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-designer-3.3.6-23.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-devel-3.3.6-23.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"qt-devel-docs-3.3.6-23.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qt / qt-MySQL / qt-ODBC / qt-PostgreSQL / qt-config / qt-designer / etc");
}
