#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0764. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119356);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3496");
  script_bugtraq_id(68105);
  script_xref(name:"RHSA", value:"2014:0764");

  script_name(english:"RHEL 6 : rubygem-openshift-origin-node (RHSA-2014:0764)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An updated rubygem-openshift-origin-node package that fixes one
security issue and several bugs is now available for Red Hat OpenShift
Enterprise 2.1.1.

The Red Hat Security Response Team has rated this update as having
Critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The rubygem-openshift-origin-node package provides basic OpenShift
node functionality.

A command injection flaw was found in rubygem-openshift-origin-node. A
remote, authenticated user permitted to install cartridges via the web
interface could use this flaw to execute arbitrary code with root
privileges on the Red Hat OpenShift Enterprise node server.
(CVE-2014-3496)

This issue was discovered by Jeremy Choi of the Red Hat HSS Pen-test
Team.

The rubygem-openshift-origin-node package has been upgraded to version
1.23.9.11. Additionally, the
rubygem-openshift-origin-container-selinux package has been upgraded
to version 0.8.1.2, as needed by the updated
rubygem-openshift-origin-node package.

This update also fixes the following bugs :

* The syslog_logger.rb implementation on nodes made incorrect use of
the Ruby Syslog library. Raw log message input was handled as a Syslog
format string, causing failures for many application operations. This
bug fix updates the implementation to correctly handle raw log message
input, and the failures no longer occur. (BZ#1096900)

* Under certain conditions, it was possible for the MCollective agent
on nodes to fail to fully initialize while checking the status of a
cartridge. This resulted in sporadic failures of rhc cartridge status.
This bug fix ensures that the agent is always fully initialized.
(BZ#1102399)

* Developers encountered syntax errors when connecting to a gear using
the 'rhc ssh' command if the gear was hosted on a node with quotas
disabled. This was due to the command trying to report quota
information but being given an empty string because quotas were
disabled. This bug fix updates the handling for reporting on quotas
when there is no information to report, and the syntax errors no
longer occur. (BZ#1107801)

* If a file containing invalid special characters was placed in an
application's ~/.env/user_vars directory, subsequent interactions with
the application using SSH or Git were refused. This was due to
problems with the node component handling the invalid characters. This
bug fix updates the node component to handle problematic files in
~/.env/user_vars; as a result, interactions with the application using
SSH or Git succeed as normal. (BZ#1096833)

All rubygem-openshift-origin-node users are advised to upgrade to this
updated package, which contains a backported patch to correct this
issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-3496"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Update the affected rubygem-openshift-origin-container-selinux and /
or rubygem-openshift-origin-node packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2014:0764";
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
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-container-selinux-0.8.1.2-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"rubygem-openshift-origin-node-1.23.9.11-1.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-openshift-origin-container-selinux / etc");
  }
}
