#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0793. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50341);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-3856");
  script_bugtraq_id(44347);
  script_xref(name:"RHSA", value:"2010:0793");

  script_name(english:"RHEL 5 : glibc (RHSA-2010:0793)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

It was discovered that the glibc dynamic linker/loader did not perform
sufficient safety checks when loading dynamic shared objects (DSOs) to
provide callbacks for its auditing API during the execution of
privileged programs. A local attacker could use this flaw to escalate
their privileges via a carefully-chosen system DSO library containing
unsafe constructors. (CVE-2010-3856)

Red Hat would like to thank Ben Hawkes and Tavis Ormandy for reporting
this issue.

All users should upgrade to these updated packages, which contain a
backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2010-3856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2010:0793"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'glibc LD_AUDIT Arbitrary DSO Load Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0793";
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
  if (rpm_check(release:"RHEL5", reference:"glibc-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"glibc-common-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"glibc-common-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"glibc-common-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", reference:"glibc-devel-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"glibc-headers-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"glibc-headers-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"glibc-headers-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"glibc-utils-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"glibc-utils-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"glibc-utils-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nscd-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"nscd-2.5-49.el5_5.7")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nscd-2.5-49.el5_5.7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-devel / glibc-headers / glibc-utils / etc");
  }
}
