#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2002:211. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(12325);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2002-0838");
  script_xref(name:"RHSA", value:"2002:211");

  script_name(english:"RHEL 2.1 : ggv (RHSA-2002:211)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages for gv, ggv, and kdegraphics fix a local buffer
overflow when reading malformed PDF or PostScript files.

[Updated 07 Jan 2003] Added fixed packages for the Itanium (IA64)
architecture.

[Updated 06 Feb 2003] Added fixed packages for Advanced Workstation
2.1

Gv and ggv are user interfaces for the Ghostscript PostScript(R)
interpreter used to display PostScript and PDF documents on an X
Window System. KGhostview is the PostScript viewer for the K Desktop
Environment.

Zen Parse found a local buffer overflow in gv version 3.5.8 and
earlier. An attacker can create a carefully crafted malformed PDF or
PostScript file in such a way that when that file is viewed arbitrary
commands can be executed.

ggv and kghostview contain code derived from gv and therefore have the
same vulnerability.

All users of gv, ggv, and kghostview are advised to upgrade to the
errata packages which contain patches to correct the vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2002-0838"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=103305778615625&w=2
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l=bugtraq&m=103305778615625&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2002:211"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ggv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdegraphics-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2002:211";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ggv-1.0.2-5.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"gv-3.5.8-18.7x")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdegraphics-2.2.2-2.1")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdegraphics-devel-2.2.2-2.1")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ggv / gv / kdegraphics / kdegraphics-devel");
  }
}
