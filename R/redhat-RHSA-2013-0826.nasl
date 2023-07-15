#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0826. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66458);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/29");

  script_cve_id(
    "CVE-2013-2549",
    "CVE-2013-2718",
    "CVE-2013-2719",
    "CVE-2013-2720",
    "CVE-2013-2721",
    "CVE-2013-2722",
    "CVE-2013-2723",
    "CVE-2013-2724",
    "CVE-2013-2725",
    "CVE-2013-2726",
    "CVE-2013-2727",
    "CVE-2013-2729",
    "CVE-2013-2730",
    "CVE-2013-2731",
    "CVE-2013-2732",
    "CVE-2013-2733",
    "CVE-2013-2734",
    "CVE-2013-2735",
    "CVE-2013-2736",
    "CVE-2013-2737",
    "CVE-2013-3337",
    "CVE-2013-3338",
    "CVE-2013-3339",
    "CVE-2013-3340",
    "CVE-2013-3341",
    "CVE-2013-3346"
  );
  script_bugtraq_id(58398, 59851);
  script_xref(name:"RHSA", value:"2013:0826");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"RHEL 5 / 6 : acroread (RHSA-2013:0826)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated acroread packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6 Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Adobe Reader allows users to view and print documents in Portable
Document Format (PDF).

This update fixes multiple security flaws in Adobe Reader. These flaws
are detailed in the Adobe Security bulletin APSB13-15, listed in the
References section. A specially crafted PDF file could cause Adobe
Reader to crash or, potentially, execute arbitrary code as the user
running Adobe Reader when opened. (CVE-2013-2549, CVE-2013-2718,
CVE-2013-2719, CVE-2013-2720, CVE-2013-2721, CVE-2013-2722,
CVE-2013-2723, CVE-2013-2724, CVE-2013-2725, CVE-2013-2726,
CVE-2013-2727, CVE-2013-2729, CVE-2013-2730, CVE-2013-2731,
CVE-2013-2732, CVE-2013-2733, CVE-2013-2734, CVE-2013-2735,
CVE-2013-2736, CVE-2013-3337, CVE-2013-3338, CVE-2013-3339,
CVE-2013-3340, CVE-2013-3341)

This update also fixes an information leak flaw in Adobe Reader.
(CVE-2013-2737)

All Adobe Reader users should install these updated packages. They
contain Adobe Reader version 9.5.5, which is not vulnerable to these
issues. All running instances of Adobe Reader must be restarted for
the update to take effect.");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/support/security/bulletins/apsb13-15.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:0826");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3340");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2719");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2718");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2735");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2734");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2737");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2736");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2731");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2730");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2733");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2732");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3341");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2549");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2729");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2726");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2727");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2724");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2725");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2722");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2723");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2720");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-2721");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3338");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3339");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3337");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2013-3346");
  script_set_attribute(attribute:"solution", value:
"Update the affected acroread and / or acroread-plugin packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-3346");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AdobeCollabSync Buffer Overflow Adobe Reader X Sandbox Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:acroread-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(5\.9|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.9 / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0826";
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
  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"acroread-9.5.5-1.el5_9")) flag++;

  if (rpm_check(release:"RHEL5", sp:"9", cpu:"i386", reference:"acroread-plugin-9.5.5-1.el5_9")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"acroread-9.5.5-1.el6_4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"acroread-plugin-9.5.5-1.el6_4")) flag++;


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
