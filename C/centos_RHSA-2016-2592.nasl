#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2592 and 
# CentOS Errata and Security Advisory 2016:2592 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95338);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-4455");
  script_xref(name:"RHSA", value:"2016:2592");

  script_name(english:"CentOS 7 : python-rhsm / subscription-manager (CESA-2016:2592)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003456.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd1a7d0e"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2016-November/003663.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d566489"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected python-rhsm and / or subscription-manager
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-4455");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-rhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-rhsm-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subscription-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subscription-manager-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subscription-manager-initial-setup-addon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subscription-manager-plugin-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:subscription-manager-plugin-ostree");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-rhsm-1.17.9-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-rhsm-certificates-1.17.9-1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subscription-manager-1.17.15-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subscription-manager-gui-1.17.15-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subscription-manager-initial-setup-addon-1.17.15-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subscription-manager-plugin-container-1.17.15-1.el7.centos")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"subscription-manager-plugin-ostree-1.17.15-1.el7.centos")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-rhsm / python-rhsm-certificates / subscription-manager / etc");
}
