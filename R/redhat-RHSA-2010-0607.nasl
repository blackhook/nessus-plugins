#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0607. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48258);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-1797");
  script_xref(name:"RHSA", value:"2010:0607");

  script_name(english:"RHEL 3 / 4 / 5 : freetype (RHSA-2010:0607)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix two security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently. The freetype packages for Red Hat Enterprise Linux
3 and 4 provide both the FreeType 1 and FreeType 2 font engines. The
freetype packages for Red Hat Enterprise Linux 5 provide only the
FreeType 2 font engine.

Two stack overflow flaws were found in the way the FreeType font
engine processed certain Compact Font Format (CFF) character strings
(opcodes). If a user loaded a specially crafted font file with an
application linked against FreeType, it could cause the application to
crash or, possibly, execute arbitrary code with the privileges of the
user running the application. (CVE-2010-1797)

Red Hat would like to thank Braden Thomas of the Apple Product
Security team for reporting these issues.

Note: CVE-2010-1797 only affects the FreeType 2 font engine.

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct these issues. The X server must be
restarted (log out, then log back in) for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-1797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2010:0607"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0607";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL3", reference:"freetype-2.1.4-16.el3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"freetype-devel-2.1.4-16.el3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"freetype-2.1.9-15.el4.8")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freetype-demos-2.1.9-15.el4.8")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freetype-devel-2.1.9-15.el4.8")) flag++;

  if (rpm_check(release:"RHEL4", reference:"freetype-utils-2.1.9-15.el4.8")) flag++;


  if (rpm_check(release:"RHEL5", reference:"freetype-2.2.1-26.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"freetype-demos-2.2.1-26.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"freetype-demos-2.2.1-26.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"freetype-demos-2.2.1-26.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"freetype-devel-2.2.1-26.el5_5")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype / freetype-demos / freetype-devel / freetype-utils");
  }
}
