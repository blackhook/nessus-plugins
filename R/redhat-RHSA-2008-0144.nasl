#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0144. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40715);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2007-0044",
    "CVE-2007-5659",
    "CVE-2007-5663",
    "CVE-2007-5666",
    "CVE-2008-0655",
    "CVE-2008-0667",
    "CVE-2008-0726"
  );
  script_bugtraq_id(21858, 27641);
  script_xref(name:"RHSA", value:"2008:0144");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"RHEL 3 / 4 / 5 : acroread (RHSA-2008:0144)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated acroread packages that fix several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The Adobe Reader allows users to view and print documents in portable
document format (PDF).

Several flaws were found in the way Adobe Reader processed malformed
PDF files. An attacker could create a malicious PDF file which could
execute arbitrary code if opened by a victim. (CVE-2007-5659,
CVE-2007-5663, CVE-2007-5666, CVE-2008-0726)

A flaw was found in the way the Adobe Reader browser plug-in honored
certain requests. A malicious PDF file could cause the browser to
request an unauthorized URL, allowing for a cross-site request forgery
attack. (CVE-2007-0044)

A flaw was found in Adobe Reader's JavaScript API DOC.print function.
A malicious PDF file could silently trigger non-interactive printing
of the document, causing multiple copies to be printed without the
users consent. (CVE-2008-0667)

Additionally, this update fixes multiple unknown flaws in Adobe
Reader. When the information regarding these flaws is made public by
Adobe, it will be added to this advisory. (CVE-2008-0655)

Note: Adobe have yet to release security fixed versions of Adobe 7.
All users of Adobe Reader are, therefore, advised to install these
updated packages. They contain Adobe Reader version 8.1.2, which is
not vulnerable to these issues.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2007-0044");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2007-5659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2007-5663");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2007-5666");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2008-0655");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2008-0667");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2008-0726");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2008:0144");
  script_set_attribute(attribute:"solution", value:
"Update the affected acroread and / or acroread-plugin packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0726");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Collab.collectEmailInfo() Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(94, 119, 189, 352, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0144";
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
  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-8.1.2-1.el3.6")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i386", reference:"acroread-plugin-8.1.2-1.el3.6")) flag++;


  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"acroread-8.1.2-1.el4.2")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"acroread-plugin-8.1.2-1.el4.2")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"acroread-plugin-8.1.2-1.el5.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acroread / acroread-plugin");
  }
}
