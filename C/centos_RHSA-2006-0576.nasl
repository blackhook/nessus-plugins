#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0576 and 
# CentOS Errata and Security Advisory 2006:0576 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(22103);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-2933");
  script_xref(name:"RHSA", value:"2006:0576");

  script_name(english:"CentOS 3 : kdebase (CESA-2006:0576)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdebase packages that resolve a security issue are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The kdebase packages provide the core applications for KDE, the K
Desktop Environment.

A flaw was found in KDE where the kdesktop_lock process sometimes
failed to terminate properly. This issue could either block the user's
ability to manually lock the desktop or prevent the screensaver to
activate, both of which could have a security impact for users who
rely on these functionalities. (CVE-2006-2933)

Please note that this issue only affected Red Hat Enterprise Linux 3.

All users of kdebase should upgrade to these updated packages, which
contain a patch to resolve this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013099.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa7a1473"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-August/013100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec210b88"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-July/013066.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7addac73"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/28");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"kdebase-3.1.3-5.11")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kdebase-devel-3.1.3-5.11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdebase / kdebase-devel");
}
