#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2592. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94555);
  script_version("2.13");
  script_cvs_date("Date: 2019/10/24 15:35:42");

  script_cve_id("CVE-2016-4455");
  script_xref(name:"RHSA", value:"2016:2592");

  script_name(english:"RHEL 7 : subscription-manager (RHSA-2016:2592)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for subscription-manager,
subscription-manager-migration-data, and python-rhsm is now available
for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The subscription-manager packages provide programs and libraries to
allow users to manage subscriptions and yum repositories from the Red
Hat entitlement platform.

The subscription-manager-migration-data package provides certificates
for migrating a system from the legacy Red Hat Network Classic (RHN)
to Red Hat Subscription Management (RHSM).

The python-rhsm packages provide a library for communicating with the
representational state transfer (REST) interface of a Red Hat Unified
Entitlement Platform. The Subscription Management tools use this
interface to manage system entitlements, certificates, and access to
content.

The following packages have been upgraded to a newer upstream version:
subscription-manager (1.17.15), python-rhsm (1.17.9),
subscription-manager-migration-data (2.0.31). (BZ#1328553, BZ#1328555,
BZ# 1328559)

Security Fix(es) :

* It was found that subscription-manager set weak permissions on files
in / var/lib/rhsm/, causing an information disclosure. A local,
unprivileged user could use this flaw to access sensitive data that
could potentially be used in a social engineering attack.
(CVE-2016-4455)

Red Hat would like to thank Robert Scheck for reporting this issue.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.3 Release Notes linked from the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2016-4455"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rhsm-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rhsm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-initial-setup-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-migration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-migration-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-plugin-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:subscription-manager-plugin-ostree");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/14");
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
  rhsa = "RHSA-2016:2592";
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
  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-rhsm-1.17.9-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rhsm-1.17.9-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-rhsm-certificates-1.17.9-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rhsm-certificates-1.17.9-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-rhsm-debuginfo-1.17.9-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rhsm-debuginfo-1.17.9-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"subscription-manager-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"subscription-manager-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"subscription-manager-debuginfo-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"subscription-manager-debuginfo-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"subscription-manager-gui-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"subscription-manager-gui-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"subscription-manager-initial-setup-addon-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"subscription-manager-initial-setup-addon-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"subscription-manager-migration-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"subscription-manager-migration-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", reference:"subscription-manager-migration-data-2.0.31-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"subscription-manager-plugin-container-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"subscription-manager-plugin-container-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"subscription-manager-plugin-ostree-1.17.15-1.el7")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"subscription-manager-plugin-ostree-1.17.15-1.el7")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-rhsm / python-rhsm-certificates / python-rhsm-debuginfo / etc");
  }
}
