#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0216 and 
# CentOS Errata and Security Advisory 2013:0216 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(64383);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-5669");
  script_xref(name:"RHSA", value:"2013:0216");

  script_name(english:"CentOS 5 / 6 : freetype (CESA-2013:0216)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently.

A flaw was found in the way the FreeType font rendering engine
processed certain Glyph Bitmap Distribution Format (BDF) fonts. If a
user loaded a specially crafted font file with an application linked
against FreeType, it could cause the application to crash or,
possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2012-5669)

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct this issue. The X server must be
restarted (log out, then log back in) for this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-February/019224.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5101d86b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019217.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db036953"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5669");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/01");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x / 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"freetype-2.2.1-32.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-demos-2.2.1-32.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"freetype-devel-2.2.1-32.el5_9.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"freetype-2.3.11-14.el6_3.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freetype-demos-2.3.11-14.el6_3.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"freetype-devel-2.3.11-14.el6_3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype / freetype-demos / freetype-devel");
}
