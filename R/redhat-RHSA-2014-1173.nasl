#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1173. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77628);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-0547", "CVE-2014-0548", "CVE-2014-0549", "CVE-2014-0550", "CVE-2014-0551", "CVE-2014-0552", "CVE-2014-0553", "CVE-2014-0554", "CVE-2014-0555", "CVE-2014-0556", "CVE-2014-0557", "CVE-2014-0559");
  script_bugtraq_id(69695, 69696, 69697, 69699, 69700, 69701, 69702, 69703, 69704, 69705, 69706, 69707);
  script_xref(name:"RHSA", value:"2014:1173");

  script_name(english:"RHEL 5 / 6 : flash-plugin (RHSA-2014:1173)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
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
These vulnerabilities are detailed in the Adobe Security Bulletin
APSB14-21, listed in the References section.

Multiple flaws were found in the way flash-plugin displayed certain
SWF content. An attacker could use these flaws to create a specially
crafted SWF file that would cause flash-plugin to crash or,
potentially, execute arbitrary code when the victim loaded a page
containing the malicious SWF content. (CVE-2014-0547, CVE-2014-0549,
CVE-2014-0550, CVE-2014-0551, CVE-2014-0552, CVE-2014-0553,
CVE-2014-0554, CVE-2014-0555, CVE-2014-0556, CVE-2014-0557,
CVE-2014-0559)

A flaw in flash-plugin could allow an attacker to bypass the
same-origin policy. (CVE-2014-0548)

All users of Adobe Flash Player should install this updated package,
which upgrades Flash Player to version 11.2.202.406."
  );
  # http://helpx.adobe.com/security/products/flash-player/apsb14-21.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://helpx.adobe.com/security/products/flash-player/apsb14-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:1173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0555"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-plugin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player copyPixelsToByteArray Method Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:flash-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1173";
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
  if (rpm_check(release:"RHEL5", reference:"flash-plugin-11.2.202.406-1.el5")) flag++;


  if (rpm_check(release:"RHEL6", reference:"flash-plugin-11.2.202.406-1.el6")) flag++;


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
