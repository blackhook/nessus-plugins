#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1178 and 
# CentOS Errata and Security Advisory 2009:1178 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40394);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-1679", "CVE-2008-1887", "CVE-2008-2315", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144", "CVE-2008-4864", "CVE-2008-5031");
  script_bugtraq_id(28715, 28749, 30491, 31932, 31976, 33187);
  script_xref(name:"RHSA", value:"2009:1178");

  script_name(english:"CentOS 3 : python (CESA-2009:1178)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated python packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Python is an interpreted, interactive, object-oriented programming
language.

When the assert() system call was disabled, an input sanitization flaw
was revealed in the Python string object implementation that led to a
buffer overflow. The missing check for negative size values meant the
Python memory allocator could allocate less memory than expected. This
could result in arbitrary code execution with the Python interpreter's
privileges. (CVE-2008-1887)

Multiple buffer and integer overflow flaws were found in the Python
Unicode string processing and in the Python Unicode and string object
implementations. An attacker could use these flaws to cause a denial
of service (Python application crash). (CVE-2008-3142, CVE-2008-5031)

Multiple integer overflow flaws were found in the Python imageop
module. If a Python application used the imageop module to process
untrusted images, it could cause the application to crash or,
potentially, execute arbitrary code with the Python interpreter's
privileges. (CVE-2008-1679, CVE-2008-4864)

Multiple integer underflow and overflow flaws were found in the Python
snprintf() wrapper implementation. An attacker could use these flaws
to cause a denial of service (memory corruption). (CVE-2008-3144)

Multiple integer overflow flaws were found in various Python modules.
An attacker could use these flaws to cause a denial of service (Python
application crash). (CVE-2008-2315, CVE-2008-3143)

Red Hat would like to thank David Remahl of the Apple Product Security
team for responsibly reporting the CVE-2008-1679 and CVE-2008-2315
issues.

All Python users should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-July/016040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe2ccaf6"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-July/016041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfc5e7af"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/28");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"python-2.2.3-6.11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"python-2.2.3-6.11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"python-devel-2.2.3-6.11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"python-devel-2.2.3-6.11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"python-docs-2.2.3-6.11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"python-docs-2.2.3-6.11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"python-tools-2.2.3-6.11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"python-tools-2.2.3-6.11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"tkinter-2.2.3-6.11")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"tkinter-2.2.3-6.11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-devel / python-docs / python-tools / tkinter");
}
