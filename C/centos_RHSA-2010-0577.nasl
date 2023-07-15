#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0577 and 
# CentOS Errata and Security Advisory 2010:0577 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48343);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-2500", "CVE-2010-2527", "CVE-2010-2541");
  script_bugtraq_id(41663, 60740, 60750);
  script_xref(name:"RHSA", value:"2010:0577");

  script_name(english:"CentOS 3 : freetype (CESA-2010:0577)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix various security issues are now
available for Red Hat Enterprise Linux 3.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently. These packages provide both the FreeType 1 and
FreeType 2 font engines.

An integer overflow flaw was found in the way the FreeType font engine
processed font files. If a user loaded a carefully-crafted font file
with an application linked against FreeType, it could cause the
application to crash or, possibly, execute arbitrary code with the
privileges of the user running the application. (CVE-2010-2500)

Several buffer overflow flaws were found in the FreeType demo
applications. If a user loaded a carefully-crafted font file with a
demo application, it could cause the application to crash or,
possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2010-2527, CVE-2010-2541)

Red Hat would like to thank Robert Swiecki of the Google Security Team
for the discovery of the CVE-2010-2500 and CVE-2010-2527 issues.

Note: All of the issues in this erratum only affect the FreeType 2
font engine.

Users are advised to upgrade to these updated packages, which contain
backported patches to correct these issues. The X server must be
restarted (log out, then log back in) for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016920.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?122b5a41"
  );
  # https://lists.centos.org/pipermail/centos-announce/2010-August/016921.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a85b27d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/17");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-2.1.4-15.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-2.1.4-15.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-demos-2.1.4-15.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-demos-2.1.4-15.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-devel-2.1.4-15.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-devel-2.1.4-15.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-utils-2.1.4-15.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"freetype-utils-2.1.4-15.el3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype / freetype-demos / freetype-devel / freetype-utils");
}
