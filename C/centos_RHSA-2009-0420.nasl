#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0420 and 
# CentOS Errata and Security Advisory 2009:0420 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(36155);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-6725", "CVE-2009-0583", "CVE-2009-0792");
  script_bugtraq_id(34184, 34337);
  script_xref(name:"RHSA", value:"2009:0420");

  script_name(english:"CentOS 3 / 4 : ghostscript (CESA-2009:0420)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ghostscript packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ghostscript is a set of software that provides a PostScript
interpreter, a set of C procedures (the Ghostscript library, which
implements the graphics capabilities in the PostScript language) and
an interpreter for Portable Document Format (PDF) files.

It was discovered that the Red Hat Security Advisory RHSA-2009:0345
did not address all possible integer overflow flaws in Ghostscript's
International Color Consortium Format library (icclib). Using
specially crafted ICC profiles, an attacker could create a malicious
PostScript or PDF file with embedded images that could cause
Ghostscript to crash or, potentially, execute arbitrary code when
opened. (CVE-2009-0792)

A missing boundary check was found in Ghostscript's CCITTFax decoding
filter. An attacker could create a specially crafted PostScript or PDF
file that could cause Ghostscript to crash or, potentially, execute
arbitrary code when opened. (CVE-2007-6725)

Users of ghostscript are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015768.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75e9d720"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015769.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26a84746"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015770.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67ba6122"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015771.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4681e20b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015912.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdb3200e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-May/015913.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?256035fa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hpijs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/15");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"ghostscript-7.05-32.1.20")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ghostscript-devel-7.05-32.1.20")) flag++;
if (rpm_check(release:"CentOS-3", reference:"hpijs-1.3-32.1.20")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ghostscript-7.07-33.2.el4_7.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ghostscript-7.07-33.2.c4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ghostscript-7.07-33.2.el4_7.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ghostscript-devel-7.07-33.2.el4_7.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ghostscript-devel-7.07-33.2.c4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ghostscript-devel-7.07-33.2.el4_7.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"ghostscript-gtk-7.07-33.2.el4_7.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"ghostscript-gtk-7.07-33.2.c4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"ghostscript-gtk-7.07-33.2.el4_7.8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-devel / ghostscript-gtk / hpijs");
}
