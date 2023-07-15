#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2578. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94541);
  script_version("2.11");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2016-7797");
  script_xref(name:"RHSA", value:"2016:2578");

  script_name(english:"RHEL 7 : pacemaker (RHSA-2016:2578)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for pacemaker is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Pacemaker cluster resource manager is a collection of technologies
working together to provide data integrity and the ability to maintain
application availability in the event of a failure.

The following packages have been upgraded to a newer upstream version:
pacemaker (1.1.15). (BZ#1304771)

Security Fix(es) :

* It was found that the connection between a pacemaker cluster and a
pacemaker_remote node could be shut down using a new unauthenticated
connection. A remote attacker could use this flaw to cause a denial of
service. (CVE-2016-7797)

Red Hat would like to thank Alain Moulle (ATOS/BULL) for reporting
this issue.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-7797"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-nagios-plugins-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:2578";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"pacemaker-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"pacemaker-cli-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-cli-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"pacemaker-cluster-libs-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"pacemaker-cluster-libs-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-cluster-libs-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"pacemaker-cts-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-cts-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"pacemaker-debuginfo-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"pacemaker-debuginfo-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-debuginfo-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"pacemaker-doc-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-doc-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"pacemaker-libs-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"pacemaker-libs-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-libs-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"pacemaker-libs-devel-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"pacemaker-libs-devel-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-libs-devel-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"pacemaker-nagios-plugins-metadata-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-nagios-plugins-metadata-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"pacemaker-remote-1.1.15-11.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"pacemaker-remote-1.1.15-11.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pacemaker / pacemaker-cli / pacemaker-cluster-libs / pacemaker-cts / etc");
  }
}
