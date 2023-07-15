#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0610. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90490);
  script_version("2.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2016-1006",
    "CVE-2016-1011",
    "CVE-2016-1012",
    "CVE-2016-1013",
    "CVE-2016-1014",
    "CVE-2016-1015",
    "CVE-2016-1016",
    "CVE-2016-1017",
    "CVE-2016-1018",
    "CVE-2016-1019",
    "CVE-2016-1020",
    "CVE-2016-1021",
    "CVE-2016-1022",
    "CVE-2016-1023",
    "CVE-2016-1024",
    "CVE-2016-1025",
    "CVE-2016-1026",
    "CVE-2016-1027",
    "CVE-2016-1028",
    "CVE-2016-1029",
    "CVE-2016-1030",
    "CVE-2016-1031",
    "CVE-2016-1032",
    "CVE-2016-1033"
  );
  script_xref(name:"RHSA", value:"2016:0610");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"RHEL 5 / 6 : flash-plugin (RHSA-2016:0610)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An update for flash-plugin is now available for Red Hat Enterprise
Linux 5 Supplementary and Red Hat Enterprise Linux 6 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The flash-plugin package contains a Mozilla Firefox compatible Adobe
Flash Player web browser plug-in.

This update upgrades Flash Player to version 11.2.202.616.

Security Fix(es) :

* This update fixes multiple vulnerabilities in Adobe Flash Player.
These vulnerabilities, detailed in the Adobe Security Bulletin listed
in the References section, could allow an attacker to create a
specially crafted SWF file that would cause flash-plugin to crash,
execute arbitrary code, or disclose sensitive information when the
victim loaded a page containing the malicious SWF content.
(CVE-2016-1006, CVE-2016-1011, CVE-2016-1012, CVE-2016-1013,
CVE-2016-1014, CVE-2016-1015, CVE-2016-1016, CVE-2016-1017,
CVE-2016-1018, CVE-2016-1019, CVE-2016-1020, CVE-2016-1021,
CVE-2016-1022, CVE-2016-1023, CVE-2016-1024, CVE-2016-1025,
CVE-2016-1026, CVE-2016-1027, CVE-2016-1028, CVE-2016-1029,
CVE-2016-1030, CVE-2016-1031, CVE-2016-1032, CVE-2016-1033)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-10.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsa16-01.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2016:0610");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1030");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1031");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1032");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1033");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1016");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1017");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1014");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1015");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1012");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1013");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1011");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1018");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1019");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1023");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1022");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1021");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1006");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1027");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1026");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1025");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1024");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1029");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1028");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-1020");
  script_set_attribute(attribute:"solution", value:
"Update the affected flash-plugin package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1019");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:flash-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0610";
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
  if (rpm_check(release:"RHEL5", reference:"flash-plugin-11.2.202.616-1.el5")) flag++;


  if (rpm_check(release:"RHEL6", reference:"flash-plugin-11.2.202.616-1.el6_7")) flag++;


  if (flag)
  {
    flash_plugin_caveat = '\n' +
      'NOTE: This vulnerability check only applies to RedHat released\n' +
      'versions of the flash-plugin package. This check does not apply to\n' +
      'Adobe released versions of the flash-plugin package, which are\n' +
      'versioned similarly and cause collisions in detection.\n\n' +

      'If you are certain you are running the Adobe released package of\n' +
      'flash-plugin and are running a version of it equal or higher to the\n' +
      'RedHat version listed above then you can consider this a false\n' +
      'positive.\n';
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat() + flash_plugin_caveat
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-plugin");
  }
}
