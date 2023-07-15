#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2024. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86862);
  script_version("2.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/08");

  script_cve_id(
    "CVE-2015-5569",
    "CVE-2015-7625",
    "CVE-2015-7626",
    "CVE-2015-7627",
    "CVE-2015-7628",
    "CVE-2015-7629",
    "CVE-2015-7630",
    "CVE-2015-7631",
    "CVE-2015-7632",
    "CVE-2015-7633",
    "CVE-2015-7634",
    "CVE-2015-7635",
    "CVE-2015-7636",
    "CVE-2015-7637",
    "CVE-2015-7638",
    "CVE-2015-7639",
    "CVE-2015-7640",
    "CVE-2015-7641",
    "CVE-2015-7642",
    "CVE-2015-7643",
    "CVE-2015-7644",
    "CVE-2015-7645",
    "CVE-2015-7647",
    "CVE-2015-7648",
    "CVE-2015-7651",
    "CVE-2015-7652",
    "CVE-2015-7653",
    "CVE-2015-7654",
    "CVE-2015-7655",
    "CVE-2015-7656",
    "CVE-2015-7657",
    "CVE-2015-7658",
    "CVE-2015-7659",
    "CVE-2015-7660",
    "CVE-2015-7661",
    "CVE-2015-7662",
    "CVE-2015-7663",
    "CVE-2015-8042",
    "CVE-2015-8043",
    "CVE-2015-8044",
    "CVE-2015-8046"
  );
  script_xref(name:"RHSA", value:"2015:2024");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"RHEL 5 : flash-plugin (RHSA-2015:2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"An updated Adobe Flash Player package that fixes multiple security
issues is now available for Red Hat Enterprise Linux 5 Supplementary.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The flash-plugin package contains a Mozilla Firefox compatible Adobe
Flash Player web browser plug-in.

This update fixes multiple vulnerabilities in Adobe Flash Player.
These vulnerabilities, detailed in the Adobe Security Bulletins
APSB15-25, APSB15-27, and APSB15-28 listed in the References section,
could allow an attacker to create a specially crafted SWF file that
would cause flash-plugin to crash, execute arbitrary code, or disclose
sensitive information when the victim loaded a page containing the
malicious SWF content. (CVE-2015-5569, CVE-2015-7625, CVE-2015-7626,
CVE-2015-7627, CVE-2015-7628, CVE-2015-7629, CVE-2015-7630,
CVE-2015-7631, CVE-2015-7632, CVE-2015-7633, CVE-2015-7634,
CVE-2015-7635, CVE-2015-7636, CVE-2015-7637, CVE-2015-7638,
CVE-2015-7639, CVE-2015-7640, CVE-2015-7641, CVE-2015-7642,
CVE-2015-7643, CVE-2015-7644, CVE-2015-7645, CVE-2015-7647,
CVE-2015-7648, CVE-2015-7651, CVE-2015-7652, CVE-2015-7653,
CVE-2015-7654, CVE-2015-7655, CVE-2015-7656, CVE-2015-7657,
CVE-2015-7658, CVE-2015-7659, CVE-2015-7660, CVE-2015-7661,
CVE-2015-7662, CVE-2015-7663, CVE-2015-8042, CVE-2015-8043,
CVE-2015-8044, CVE-2015-8046)

All users of Adobe Flash Player should install this updated package,
which upgrades Flash Player to version 11.2.202.548.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-25.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-27.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-28.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2015:2024");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7643");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7644");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7633");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7634");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7626");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7627");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7625");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7631");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7630");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-5569");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7632");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7628");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7629");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7635");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7636");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7637");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7638");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7639");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7640");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7641");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7642");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7648");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7645");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7647");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7657");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7656");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7655");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7654");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7653");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7652");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7651");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8046");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7662");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7663");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7660");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7661");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7659");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-7658");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8044");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8043");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2015-8042");
  script_set_attribute(attribute:"solution", value:
"Update the affected flash-plugin package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8046");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:flash-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
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
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2024";
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
  if (rpm_check(release:"RHEL5", reference:"flash-plugin-11.2.202.548-1.el5")) flag++;

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
