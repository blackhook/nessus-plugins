#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2697. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(87665);
  script_version("2.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2015-8459",
    "CVE-2015-8460",
    "CVE-2015-8634",
    "CVE-2015-8635",
    "CVE-2015-8636",
    "CVE-2015-8638",
    "CVE-2015-8639",
    "CVE-2015-8640",
    "CVE-2015-8641",
    "CVE-2015-8642",
    "CVE-2015-8643",
    "CVE-2015-8644",
    "CVE-2015-8645",
    "CVE-2015-8646",
    "CVE-2015-8647",
    "CVE-2015-8648",
    "CVE-2015-8649",
    "CVE-2015-8650",
    "CVE-2015-8651",
    "CVE-2016-0959"
  );
  script_xref(name:"RHSA", value:"2015:2697");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"RHEL 5 / 6 : flash-plugin (RHSA-2015:2697)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An updated Adobe Flash Player package that fixes multiple security
issues is now available for Red Hat Enterprise Linux 5 and 6
Supplementary.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The flash-plugin package contains a Mozilla Firefox compatible Adobe
Flash Player web browser plug-in.

This update fixes multiple vulnerabilities in Adobe Flash Player.
These vulnerabilities, detailed in the Adobe Security Bulletin
APSB16-01 listed in the References section, could allow an attacker to
create a specially crafted SWF file that would cause flash-plugin to
crash, execute arbitrary code, or disclose sensitive information when
the victim loaded a page containing the malicious SWF content.
(CVE-2015-8459, CVE-2015-8460, CVE-2015-8634, CVE-2015-8635,
CVE-2015-8636, CVE-2015-8638, CVE-2015-8639, CVE-2015-8640,
CVE-2015-8641, CVE-2015-8642, CVE-2015-8643, CVE-2015-8644,
CVE-2015-8645, CVE-2015-8646, CVE-2015-8647, CVE-2015-8648,
CVE-2015-8649, CVE-2015-8650, CVE-2015-8651)

All users of Adobe Flash Player should install this updated package,
which upgrades Flash Player to version 11.2.202.559.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-01.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:2697");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8650");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8460");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8648");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8651");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8644");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8649");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8641");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8646");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8638");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8459");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8640");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8634");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8635");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8636");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8642");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8645");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8643");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8647");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2016-0959");
  script_set_attribute(attribute:"solution", value:
"Update the affected flash-plugin package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0959");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-8459");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:flash-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2015:2697";
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
  if (rpm_check(release:"RHEL5", reference:"flash-plugin-11.2.202.559-1.el5")) flag++;


  if (rpm_check(release:"RHEL6", reference:"flash-plugin-11.2.202.559-1.el6_7")) flag++;


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
