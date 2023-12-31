#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1027. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27852);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-4033", "CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367);
  script_xref(name:"RHSA", value:"2007:1027");

  script_name(english:"RHEL 4 / 5 : tetex (RHSA-2007:1027)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tetex packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

TeTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input, and creates a typesetter-independent
DeVice Independent (dvi) file as output.

Alin Rad Pop discovered several flaws in the handling of PDF files. An
attacker could create a malicious PDF file that would cause TeTeX to
crash or potentially execute arbitrary code when opened.
(CVE-2007-4352, CVE-2007-5392, CVE-2007-5393)

A flaw was found in the t1lib library, used in the handling of Type 1
fonts. An attacker could create a malicious file that would cause
TeTeX to crash, or potentially execute arbitrary code when opened.
(CVE-2007-4033)

Users are advised to upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-4033"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-4352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-5392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-5393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2007:1027"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:1027";
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
  if (rpm_check(release:"RHEL4", reference:"tetex-2.0.2-22.0.1.EL4.10")) flag++;

  if (rpm_check(release:"RHEL4", reference:"tetex-afm-2.0.2-22.0.1.EL4.10")) flag++;

  if (rpm_check(release:"RHEL4", reference:"tetex-doc-2.0.2-22.0.1.EL4.10")) flag++;

  if (rpm_check(release:"RHEL4", reference:"tetex-dvips-2.0.2-22.0.1.EL4.10")) flag++;

  if (rpm_check(release:"RHEL4", reference:"tetex-fonts-2.0.2-22.0.1.EL4.10")) flag++;

  if (rpm_check(release:"RHEL4", reference:"tetex-latex-2.0.2-22.0.1.EL4.10")) flag++;

  if (rpm_check(release:"RHEL4", reference:"tetex-xdvi-2.0.2-22.0.1.EL4.10")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-afm-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-afm-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-afm-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-doc-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-doc-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-doc-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-dvips-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-dvips-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-dvips-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-fonts-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-fonts-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-fonts-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-latex-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-latex-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-latex-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-xdvi-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-xdvi-3.0-33.2.el5_1.2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-xdvi-3.0-33.2.el5_1.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-doc / tetex-dvips / tetex-fonts / etc");
  }
}
