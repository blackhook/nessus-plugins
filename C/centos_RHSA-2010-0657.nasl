#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0657 and 
# CentOS Errata and Security Advisory 2010:0657 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48912);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-5079");
  script_xref(name:"RHSA", value:"2010:0657");

  script_name(english:"CentOS 4 : gdm (CESA-2010:0657)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gdm package that fixes one security issue and one bug is
now available for Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The GNOME Display Manager (GDM) is a configurable re-implementation of
XDM, the X Display Manager. GDM allows you to log in to your system
with the X Window System running, and supports running several
different X sessions on your local machine at the same time.

A flaw was found in the way the gdm package was built. The gdm package
was missing TCP wrappers support on 64-bit platforms, which could
result in an administrator believing they had access restrictions
enabled when they did not. (CVE-2007-5079)

This update also fixes the following bug :

* sometimes the system would hang instead of properly shutting down
when a user chose 'Shut down' from the login screen. (BZ#625818)

All users should upgrade to this updated package, which contains
backported patches to correct these issues. GDM must be restarted for
this update to take effect. Rebooting achieves this, but changing the
runlevel from 5 to 3 and back to 5 also restarts GDM."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016948.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41791edd"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016949.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9880ea6c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gdm package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"gdm-2.6.0.5-7.rhel4.19.el4_8.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"gdm-2.6.0.5-7.rhel4.19.el4_8.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdm");
}
