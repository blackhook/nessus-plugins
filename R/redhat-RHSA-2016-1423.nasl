#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1423. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92044);
  script_version("2.19");
  script_cvs_date("Date: 2019/10/24 15:35:41");

  script_cve_id("CVE-2016-4172", "CVE-2016-4173", "CVE-2016-4174", "CVE-2016-4175", "CVE-2016-4176", "CVE-2016-4177", "CVE-2016-4178", "CVE-2016-4179", "CVE-2016-4180", "CVE-2016-4181", "CVE-2016-4182", "CVE-2016-4183", "CVE-2016-4184", "CVE-2016-4185", "CVE-2016-4186", "CVE-2016-4187", "CVE-2016-4188", "CVE-2016-4189", "CVE-2016-4190", "CVE-2016-4217", "CVE-2016-4218", "CVE-2016-4219", "CVE-2016-4220", "CVE-2016-4221", "CVE-2016-4222", "CVE-2016-4223", "CVE-2016-4224", "CVE-2016-4225", "CVE-2016-4226", "CVE-2016-4227", "CVE-2016-4228", "CVE-2016-4229", "CVE-2016-4230", "CVE-2016-4231", "CVE-2016-4232", "CVE-2016-4233", "CVE-2016-4234", "CVE-2016-4235", "CVE-2016-4236", "CVE-2016-4237", "CVE-2016-4238", "CVE-2016-4239", "CVE-2016-4240", "CVE-2016-4241", "CVE-2016-4242", "CVE-2016-4243", "CVE-2016-4244", "CVE-2016-4245", "CVE-2016-4246", "CVE-2016-4247", "CVE-2016-4248", "CVE-2016-4249", "CVE-2016-7020");
  script_xref(name:"RHSA", value:"2016:1423");

  script_name(english:"RHEL 5 / 6 : flash-plugin (RHSA-2016:1423)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for flash-plugin is now available for Red Hat Enterprise
Linux 5 Supplementary and Red Hat Enterprise Linux 6 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The flash-plugin package contains a Mozilla Firefox compatible Adobe
Flash Player web browser plug-in.

This update upgrades Flash Player to version 11.2.202.632.

Security Fix(es) :

* This update fixes multiple vulnerabilities in Adobe Flash Player.
These vulnerabilities, detailed in the Adobe Security Bulletin listed
in the References section, could allow an attacker to create a
specially crafted SWF file that would cause flash-plugin to crash,
execute arbitrary code, or disclose sensitive information when the
victim loaded a page containing the malicious SWF content.
(CVE-2016-4172, CVE-2016-4173, CVE-2016-4174, CVE-2016-4175,
CVE-2016-4176, CVE-2016-4177, CVE-2016-4178, CVE-2016-4179,
CVE-2016-4180, CVE-2016-4181, CVE-2016-4182, CVE-2016-4183,
CVE-2016-4184, CVE-2016-4185, CVE-2016-4186, CVE-2016-4187,
CVE-2016-4188, CVE-2016-4189, CVE-2016-4190, CVE-2016-4217,
CVE-2016-4218, CVE-2016-4219, CVE-2016-4220, CVE-2016-4221,
CVE-2016-4222, CVE-2016-4223, CVE-2016-4224, CVE-2016-4225,
CVE-2016-4226, CVE-2016-4227, CVE-2016-4228, CVE-2016-4229,
CVE-2016-4230, CVE-2016-4231, CVE-2016-4232, CVE-2016-4233,
CVE-2016-4234, CVE-2016-4235, CVE-2016-4236, CVE-2016-4237,
CVE-2016-4238, CVE-2016-4239, CVE-2016-4240, CVE-2016-4241,
CVE-2016-4242, CVE-2016-4243, CVE-2016-4244, CVE-2016-4245,
CVE-2016-4246, CVE-2016-4247, CVE-2016-4248, CVE-2016-4249)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://helpx.adobe.com/security/products/flash-player/apsb16-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:1423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4217"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7020"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-plugin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:flash-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2016:1423";
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
  if (rpm_check(release:"RHEL5", reference:"flash-plugin-11.2.202.632-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL6", reference:"flash-plugin-11.2.202.632-1.el6_8")) flag++;

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
