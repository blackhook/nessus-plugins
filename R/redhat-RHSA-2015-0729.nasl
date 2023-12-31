#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0729. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82292);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/05");

  script_cve_id("CVE-2015-1815");
  script_bugtraq_id(73374);
  script_xref(name:"RHSA", value:"2015:0729");

  script_name(english:"RHEL 5 / 6 / 7 : setroubleshoot (RHSA-2015:0729)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updated setroubleshoot packages that fix one security issue are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The setroubleshoot packages provide tools to help diagnose SELinux
problems. When Access Vector Cache (AVC) messages are returned, an
alert can be generated that provides information about the problem and
helps to track its resolution.

It was found that setroubleshoot did not sanitize file names supplied
in a shell command look-up for RPMs associated with access violation
reports. An attacker could use this flaw to escalate their privileges
on the system by supplying a specially crafted file to the underlying
shell command. (CVE-2015-1815)

Red Hat would like to thank Sebastian Krahmer of the SUSE Security
Team for reporting this issue.

All setroubleshoot users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:0729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-1815"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:setroubleshoot-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:0729";
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
  if (rpm_check(release:"RHEL5", reference:"setroubleshoot-2.0.5-7.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", reference:"setroubleshoot-server-2.0.5-7.el5_11")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"setroubleshoot-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"setroubleshoot-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"setroubleshoot-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"setroubleshoot-debuginfo-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"setroubleshoot-debuginfo-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"setroubleshoot-debuginfo-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"setroubleshoot-doc-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"setroubleshoot-doc-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"setroubleshoot-doc-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"setroubleshoot-server-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"setroubleshoot-server-3.0.47-6.el6_6.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"setroubleshoot-server-3.0.47-6.el6_6.1")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"setroubleshoot-3.2.17-4.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"setroubleshoot-3.2.17-4.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"setroubleshoot-debuginfo-3.2.17-4.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"setroubleshoot-debuginfo-3.2.17-4.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"setroubleshoot-server-3.2.17-4.1.el7_1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"setroubleshoot-server-3.2.17-4.1.el7_1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "setroubleshoot / setroubleshoot-debuginfo / setroubleshoot-doc / etc");
  }
}
