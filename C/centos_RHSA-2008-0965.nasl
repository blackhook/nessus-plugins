#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0965 and 
# CentOS Errata and Security Advisory 2008:0965 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34503);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-7234", "CVE-2008-4690");
  script_bugtraq_id(15395);
  script_xref(name:"RHSA", value:"2008:0965");

  script_name(english:"CentOS 3 / 4 / 5 : lynx (CESA-2008:0965)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated lynx package that corrects two security issues is now
available for Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Lynx is a text-based Web browser.

An arbitrary command execution flaw was found in the Lynx 'lynxcgi:'
URI handler. An attacker could create a web page redirecting to a
malicious URL that could execute arbitrary code as the user running
Lynx in the non-default 'Advanced' user mode. (CVE-2008-4690)

Note: In these updated lynx packages, Lynx will always prompt users
before loading a 'lynxcgi:' URI. Additionally, the default lynx.cfg
configuration file now marks all 'lynxcgi:' URIs as untrusted by
default.

A flaw was found in a way Lynx handled '.mailcap' and '.mime.types'
configuration files. Files in the browser's current working directory
were opened before those in the user's home directory. A local
attacker, able to convince a user to run Lynx in a directory under
their control, could possibly execute arbitrary commands as the user
running Lynx. (CVE-2006-7234)

All users of Lynx are advised to upgrade to this updated package,
which contains backported patches correcting these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015350.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02eef948"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015351.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1525496"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015352.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7b1b1d7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015353.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fae6bf1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015358.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5220406d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015359.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0706c97f"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015361.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1efb3594"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-October/015362.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86c96ef1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lynx package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lynx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"lynx-2.8.5-11.3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"lynx-2.8.5-18.2.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"lynx-2.8.5-18.2.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"lynx-2.8.5-18.2.el4_7.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"lynx-2.8.5-28.1.el5_2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lynx");
}
