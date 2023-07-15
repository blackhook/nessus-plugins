#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:499 and 
# CentOS Errata and Security Advisory 2005:499 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21832);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1686");
  script_bugtraq_id(13699);
  script_xref(name:"RHSA", value:"2005:499");

  script_name(english:"CentOS 3 / 4 : gedit (CESA-2005:499)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gedit package that fixes a file name format string
vulnerability is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team

gEdit is a small text editor designed specifically for the GNOME GUI
desktop.

A file name format string vulnerability has been discovered in gEdit.
It is possible for an attacker to create a file with a carefully
crafted name which, when the file is opened, executes arbitrary
instructions on a victim's machine. Although it is unlikely that a
user would manually open a file with such a carefully crafted file
name, a user could, for example, be tricked into opening such a file
from within an email client. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-1686 to this
issue.

Users of gEdit should upgrade to this updated package, which contains
a backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011819.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?151d6764"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011820.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?204eba70"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011829.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9c89240"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011830.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16a9deea"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a71f614"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-June/011843.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f573724d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gedit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gedit-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/13");
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
if (rpm_check(release:"CentOS-3", reference:"gedit-2.2.2-4.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gedit-2.8.1-4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gedit-devel-2.8.1-4")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gedit / gedit-devel");
}
