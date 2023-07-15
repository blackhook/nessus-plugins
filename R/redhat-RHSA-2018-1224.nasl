#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1224. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109338);
  script_version("1.9");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2018-1106");
  script_xref(name:"RHSA", value:"2018:1224");

  script_name(english:"RHEL 7 : PackageKit (RHSA-2018:1224)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for PackageKit is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PackageKit is a D-Bus abstraction layer that allows the session user
to manage packages in a secure way using a cross-distribution,
cross-architecture API.

Security Fix(es) :

* PackageKit: authentication bypass allows to install signed packages
without administrator privileges (CVE-2018-1106)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Matthias Gerstner (SUSE) for reporting
this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1106"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PackageKit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PackageKit-command-not-found");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PackageKit-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PackageKit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PackageKit-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PackageKit-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PackageKit-gstreamer-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PackageKit-gtk3-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PackageKit-yum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:PackageKit-yum-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2018:1224";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL7", reference:"PackageKit-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"PackageKit-command-not-found-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"PackageKit-command-not-found-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"PackageKit-cron-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"PackageKit-cron-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"PackageKit-debuginfo-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"PackageKit-glib-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"PackageKit-glib-devel-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"PackageKit-gstreamer-plugin-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"PackageKit-gstreamer-plugin-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", reference:"PackageKit-gtk3-module-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"PackageKit-yum-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"PackageKit-yum-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"PackageKit-yum-plugin-1.1.5-2.el7_5")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"PackageKit-yum-plugin-1.1.5-2.el7_5")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit / PackageKit-command-not-found / PackageKit-cron / etc");
  }
}
