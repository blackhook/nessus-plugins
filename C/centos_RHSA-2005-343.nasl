#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:343 and 
# CentOS Errata and Security Advisory 2005:343 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21806);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0891");
  script_xref(name:"RHSA", value:"2005:343");

  script_name(english:"CentOS 3 / 4 : gdk-pixbuf (CESA-2005:343)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdk-pixbuf packages that fix a double free vulnerability are
now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The gdk-pixbuf package contains an image loading library used with the
GNOME GUI desktop environment.

A bug was found in the way gdk-pixbuf processes BMP images. It is
possible that a specially crafted BMP image could cause a denial of
service attack on applications linked against gdk-pixbuf. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0891 to this issue.

Users of gdk-pixbuf are advised to upgrade to these packages, which
contain a backported patch and is not vulnerable to this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011533.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58cd6a12"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011534.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ffa0544"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011537.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d0f3e02"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011541.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad2a194d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-April/011544.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19385042"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdk-pixbuf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/05");
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
if (rpm_check(release:"CentOS-3", reference:"gdk-pixbuf-0.22.0-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gdk-pixbuf-devel-0.22.0-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gdk-pixbuf-gnome-0.22.0-12.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gdk-pixbuf-0.22.0-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gdk-pixbuf-devel-0.22.0-16.el4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf / gdk-pixbuf-devel / gdk-pixbuf-gnome");
}
