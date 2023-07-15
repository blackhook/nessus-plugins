#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0301. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52161);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-0562", "CVE-2011-0563", "CVE-2011-0565", "CVE-2011-0566", "CVE-2011-0567", "CVE-2011-0585", "CVE-2011-0586", "CVE-2011-0587", "CVE-2011-0589", "CVE-2011-0590", "CVE-2011-0591", "CVE-2011-0592", "CVE-2011-0593", "CVE-2011-0594", "CVE-2011-0595", "CVE-2011-0596", "CVE-2011-0598", "CVE-2011-0599", "CVE-2011-0600", "CVE-2011-0602", "CVE-2011-0603", "CVE-2011-0604", "CVE-2011-0606");
  script_bugtraq_id(46187, 46198, 46199, 46201, 46202, 46204, 46207, 46208, 46209, 46210, 46211, 46212, 46213, 46214, 46216, 46217, 46218, 46219, 46220, 46221, 46222, 46251, 46252);
  script_xref(name:"RHSA", value:"2011:0301");

  script_name(english:"RHEL 4 / 5 / 6 : acroread (RHSA-2011:0301)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated acroread packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 Extras and Red Hat Enterprise
Linux 5 and 6 Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Adobe Reader allows users to view and print documents in Portable
Document Format (PDF).

This update fixes multiple vulnerabilities in Adobe Reader. These
vulnerabilities are detailed on the Adobe security page APSB11-03,
listed in the References section.

A specially crafted PDF file could cause Adobe Reader to crash or,
potentially, execute arbitrary code as the user running Adobe Reader
when opened. (CVE-2011-0562, CVE-2011-0563, CVE-2011-0565,
CVE-2011-0566, CVE-2011-0567, CVE-2011-0585, CVE-2011-0586,
CVE-2011-0589, CVE-2011-0590, CVE-2011-0591, CVE-2011-0592,
CVE-2011-0593, CVE-2011-0594, CVE-2011-0595, CVE-2011-0596,
CVE-2011-0598, CVE-2011-0599, CVE-2011-0600, CVE-2011-0602,
CVE-2011-0603, CVE-2011-0606)

Multiple security flaws were found in Adobe reader. A specially
crafted PDF file could cause cross-site scripting (XSS) attacks
against the user running Adobe Reader when opened. (CVE-2011-0587,
CVE-2011-0604)

All Adobe Reader users should install these updated packages. They
contain Adobe Reader version 9.4.2, which is not vulnerable to these
issues. All running instances of Adobe Reader must be restarted for
the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0565"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0595"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2011-0606"
  );
  # http://www.adobe.com/support/security/bulletins/apsb11-03.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.adobe.com/support/security/bulletins/apsb11-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2011:0301"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected acroread and / or acroread-plugin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0301";
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
  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"acroread-9.4.2-1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i386", reference:"acroread-plugin-9.4.2-1.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"acroread-9.4.2-1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"acroread-plugin-9.4.2-1.el5")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"acroread-9.4.2-3.el6_0")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"acroread-plugin-9.4.2-3.el6_0")) flag++;


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
