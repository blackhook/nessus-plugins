#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3427. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105210);
  script_version("3.8");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2016-6338");
  script_xref(name:"RHSA", value:"2017:3427");

  script_name(english:"RHEL 7 : org.ovirt.engine-root (RHSA-2017:3427)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for org.ovirt.engine-root is now available for Red Hat
Virtualization Manager version 4.1.

Red Hat Product Security has rated this update as having a security
impact of Low. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link (s) in the References section.

The Red Hat Enterprise Virtualization Manager is a centralized
management platform that allows system administrators to view and
manage virtual machines. The Manager provides a comprehensive range of
features including search capabilities, resource management, live
migrations, and virtual infrastructure provisioning.

The Manager is a JBoss Application Server application that provides
several interfaces through which the virtual environment can be
accessed and interacted with, including an Administration Portal, a
User Portal, and a Representational State Transfer (REST) Application
Programming Interface (API).

The following packages have been upgraded to a later upstream version:
org.ovirt.engine-root (4.1.8.2). (BZ#1483576)

Security Fix(es) :

* It was discovered that the ovirt-engine webadmin session would not
properly enforce timeouts. Browser sessions would remain logged in
beyond the administratively configured session timeout period.
(CVE-2016-6338)

This issue was discovered by Greg Sheremeta (Red Hat).

Bug Fix(es) :

* You can now set the Initialization of a virtual machine to an empty
value through the REST API. (BZ#1513684)

Enhancement(s) :

* There are several cluster and host settings which require
reinstallation of the host if changed. The requirement to reinstall
was always mentioned in documentation and a WARNING event was raised.
With this release, the Administration Portal now also shows an
exclamation mark icon for each host that needs to be reinstalled. When
an exclamation mark icon is shown, you can find the details about it
in the Action Items section of the host's details view. (BZ#1501793)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:3427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-6338"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-extensions-api-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-extensions-api-impl-javadoc");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-userportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ovirt-engine-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2017:3427";
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
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-backend-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-dbscripts-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-extensions-api-impl-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-extensions-api-impl-javadoc-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-lib-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-restapi-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-base-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-ovirt-engine-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-ovirt-engine-common-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-vmconsole-proxy-helper-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-setup-plugin-websocket-proxy-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-tools-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-tools-backup-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-userportal-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-vmconsole-proxy-helper-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-webadmin-portal-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ovirt-engine-websocket-proxy-4.1.8.2-0.1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rhevm-4.1.8.2-0.1.el7")) flag++;

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
