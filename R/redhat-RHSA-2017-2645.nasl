#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2645. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103045);
  script_version("3.10");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-7538");
  script_xref(name:"RHSA", value:"2017:2645");

  script_name(english:"RHEL 6 : Satellite Server (RHSA-2017:2645)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for satellite-schema, spacewalk-backend, spacewalk-java, and
spacewalk-schema is now available for Red Hat Satellite 5.8 and Red
Hat Satellite 5.8 ELS.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Spacewalk is an Open Source systems management solution that provides
system provisioning, configuration and patching capabilities.

Red Hat Satellite is a system management tool for Linux-based
infrastructures. It allows for provisioning, monitoring, and the
remote management of multiple Linux deployments with a single,
centralized tool.

Security Fix(es) :

* A cross-site scripting (XSS) flaw was found in how an organization
name is displayed in Satellite 5. A user able to change an
organization's name could exploit this flaw to perform XSS attacks
against other Satellite users. (CVE-2017-7538)

This issue was discovered by Ales Dujicek (Red Hat).

Bug Fix(es) :

* Prior to this update, transferring content between Satellites using
Inter-Satellite Synchronization or channel-dumps failed to transfer
the product-name related to channels. This interfered with the process
of moving a server between EUS channels. The 'satellite-export' tool
now correctly provides associated product-names, fixing this behavior.
(BZ# 1446271)

* Prior to this update, the API call 'schedule.failSystemAction()'
allowed overwriting a system's event history. This is undesirable from
an auditing standpoint. The API now no longer allows affecting
completed or failed events. (BZ#1455887)

* Prior to this update, organization administrators who were not
allowed to change their organization's attributes could do so by
modifying form elements. The associated form controller no longer
allows this behavior. (BZ#1458722)

* Prior to this update, the 'download' tool's retry limit would be
incorrect if there were more available mirrors than its retry count.
It could also produce a harmless but unhelpful traceback in some
situations. Both of these behaviors have been fixed. (BZ#1458765)

* Prior to this update, it was possible for parallel registrations
using reactivation keys, that were creating snapshot entries, to
occasionally deadlock. Both the reactivation-key registration and
snapshot-creation paths have been updated to prevent these deadlocks.
(BZ#1458880)

* Prior to this update, if there was some problem with a single
erratum in a given repository, the 'reposync' command would complain
and exit. The tool now logs such errors but continues to synchronize
any remaining errata. (BZ #1466229)

* The Satellite 5.8 release failed to include an update to a
registration-failure error message that had been released for
Satellite 5.7. This restores the missing update. (BZ#1467632)

* Prior to this update, the list of systems in the System Set Manager
failed to display the correct icons for a system's update status. This
has been corrected. (BZ#1475067)

* Prior to this update, a timing window in the 'cdn-sync' command,
when synchronizing multiple channels at once, could cause some of the
synchronization attempts to be refused with a 403 error. This update
fixes the timing window so that multiple syncs should now work
reliably. (BZ# 1476924)

* Prior to this update, attempting to view the systems in the System
Set Manager that are affected by a given erratum would result in an
internal server error. This has been fixed. (BZ#1477508)

* Prior to this update, using 'cdn-sync --no-packages' on a specific
channel would disassociate all packages from that channel. This
behavior has been fixed, so that '--no-packages' now just skips that
step as intended. (BZ# 1477667)"
  );
  # https://access.redhat.com/site/articles/273633
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/273633"
  );
  # https://access.redhat.com/site/articles/11258
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/11258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-7538"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-cdn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2645";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"spacewalk-admin-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

  if (rpm_check(release:"RHEL6", reference:"satellite-schema-5.8.0.33-1.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-app-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-app-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-applet-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-applet-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-cdn-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-cdn-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-config-files-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-config-files-common-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-common-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-config-files-tool-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-tool-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-iss-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-iss-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-iss-export-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-iss-export-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-libs-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-libs-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-package-push-server-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-package-push-server-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-server-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-server-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-sql-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-sql-oracle-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-oracle-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-sql-postgresql-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-postgresql-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-tools-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-tools-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-xml-export-libs-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-xml-export-libs-2.5.3-151.el6")) flag++;
  if (rpm_exists(rpm:"spacewalk-backend-xmlrpc-2.5.3", release:"RHEL6") && rpm_check(release:"RHEL6", reference:"spacewalk-backend-xmlrpc-2.5.3-151.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-2.5.14-95.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-config-2.5.14-95.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-lib-2.5.14-95.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-oracle-2.5.14-95.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-java-postgresql-2.5.14-95.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-schema-2.5.1-50.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-taskomatic-2.5.14-95.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "satellite-schema / spacewalk-backend / spacewalk-backend-app / etc");
  }
}
