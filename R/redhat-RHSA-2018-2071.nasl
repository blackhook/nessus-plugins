#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2071. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110796);
  script_version("1.7");
  script_cvs_date("Date: 2019/10/24 15:35:45");

  script_cve_id("CVE-2018-1072", "CVE-2018-1075");
  script_xref(name:"RHSA", value:"2018:2071");

  script_name(english:"RHEL 7 : Virtualization Manager (RHSA-2018:2071)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for org.ovirt.engine-root is now available for Red Hat
Virtualization Manager 4.2.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The Red Hat Virtualization Manager is a centralized management
platform that allows system administrators to view and manage virtual
machines. The Manager provides a comprehensive range of features
including search capabilities, resource management, live migrations,
and virtual infrastructure provisioning.

The Manager is a JBoss Application Server application that provides
several interfaces through which the virtual environment can be
accessed and interacted with, including an Administration Portal, a
User Portal, and a Representational State Transfer (REST) Application
Programming Interface (API).

The following packages have been upgraded to a later version :

* org.ovirt.engine-root (4.2.4.5). (BZ#1576752)

Security Fix(es) :

* ovirt-engine: Unfiltered password when choosing manual db
provisioning (CVE-2018-1075)

* ovirt-engine-setup: unfiltered db password in engine-backup log
(CVE-2018-1072)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

These issues were discovered by Yedidyah Bar David (Red Hat).

Bug Fix(es) :

* This update enables engine-setup to upgrade PostgreSQL 9.2 to 9.5,
even when the locale of the 9.2 database is different from the system
locale. (BZ#1579268)

* This update fixes an inefficient query that is generated when users
click on the 'Users' tab in the Administration Portal. The fix ensures
that the tab loads quicker. (BZ#1583619)

Enhancement(s) :

* The storage domain's General sub-tab in the Administration Portal
now shows the number of images on the storage domain under the rubric
'Images', this corresponds to the number of LVs on a block domain.
(BZ#1587885)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:2071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1075"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-extensions-api-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-extensions-api-impl-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-health-check-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-tools-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/29");
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
  rhsa = "RHSA-2018:2071";
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
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-backend-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-dbscripts-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-extensions-api-impl-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-extensions-api-impl-javadoc-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-health-check-bundler-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-lib-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-restapi-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-base-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-ovirt-engine-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-ovirt-engine-common-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-vmconsole-proxy-helper-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-websocket-proxy-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-tools-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-tools-backup-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-vmconsole-proxy-helper-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-webadmin-portal-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-websocket-proxy-4.2.4.5-0.1.el7_3")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rhvm-4.2.4.5-0.1.el7_3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ovirt-engine / ovirt-engine-backend / ovirt-engine-dbscripts / etc");
  }
}
