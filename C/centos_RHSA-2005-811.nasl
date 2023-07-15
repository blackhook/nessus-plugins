#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:811 and 
# CentOS Errata and Security Advisory 2005:811 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21867);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2975", "CVE-2005-3186");
  script_xref(name:"RHSA", value:"2005:811");

  script_name(english:"CentOS 3 / 4 : gtk2 (CESA-2005:811)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gtk2 packages that fix two security issues are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The gtk2 package contains the GIMP ToolKit (GTK+), a library for
creating graphical user interfaces for the X Window System.

A bug was found in the way gtk2 processes XPM images. An attacker
could create a carefully crafted XPM file in such a way that it could
cause an application linked with gtk2 to execute arbitrary code when
the file was opened by a victim. The Common Vulnerabilities and
Exposures project has assigned the name CVE-2005-3186 to this issue.

Ludwig Nussel discovered an infinite-loop denial of service bug in the
way gtk2 processes XPM images. An attacker could create a carefully
crafted XPM file in such a way that it could cause an application
linked with gtk2 to stop responding when the file was opened by a
victim. The Common Vulnerabilities and Exposures project has assigned
the name CVE-2005-2975 to this issue.

Users of gtk2 are advised to upgrade to these updated packages, which
contain backported patches and are not vulnerable to these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012420.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58fb95d4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012421.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?709c03c7"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012422.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b3414c9"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012423.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0839906a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012427.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8dff336d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-November/012429.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40b7a21c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gtk2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/15");
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
if (rpm_check(release:"CentOS-3", reference:"gtk2-2.2.4-19")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gtk2-devel-2.2.4-19")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gtk2-2.4.13-18")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gtk2-devel-2.4.13-18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gtk2 / gtk2-devel");
}
