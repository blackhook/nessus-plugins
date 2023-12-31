#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0003. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(29876);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-5497");
  script_bugtraq_id(26772);
  script_xref(name:"RHSA", value:"2008:0003");

  script_name(english:"RHEL 2.1 / 3 / 4 / 5 : e2fsprogs (RHSA-2008:0003)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated e2fsprogs packages that fix several security issues are now
available for Red Hat Enterprise Linux.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The e2fsprogs packages contain a number of utilities for creating,
checking, modifying, and correcting any inconsistencies in second and
third extended (ext2/ext3) file systems.

Multiple integer overflow flaws were found in the way e2fsprogs
processes file system content. If a victim opens a carefully crafted
file system with a program using e2fsprogs, it may be possible to
execute arbitrary code with the permissions of the victim. It may be
possible to leverage this flaw in a virtualized environment to gain
access to other virtualized hosts. (CVE-2007-5497)

Red Hat would like to thank Rafal Wojtczuk of McAfee Avert Research
for responsibly disclosing these issues.

Users of e2fsprogs are advised to upgrade to these updated packages,
which contain a backported patch to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-5497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2008:0003"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected e2fsprogs, e2fsprogs-devel and / or e2fsprogs-libs
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:e2fsprogs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:e2fsprogs-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(2\.1|3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0003";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"e2fsprogs-1.26-1.73")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"e2fsprogs-devel-1.26-1.73")) flag++;


  if (rpm_check(release:"RHEL3", reference:"e2fsprogs-1.32-15.4")) flag++;

  if (rpm_check(release:"RHEL3", reference:"e2fsprogs-devel-1.32-15.4")) flag++;


  if (rpm_check(release:"RHEL4", reference:"e2fsprogs-1.35-12.11.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"e2fsprogs-devel-1.35-12.11.el4_6.1")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"e2fsprogs-1.39-10.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"e2fsprogs-1.39-10.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"e2fsprogs-1.39-10.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"e2fsprogs-devel-1.39-10.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"e2fsprogs-libs-1.39-10.el5_1.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "e2fsprogs / e2fsprogs-devel / e2fsprogs-libs");
  }
}
