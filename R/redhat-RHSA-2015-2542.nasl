#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2542. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87194);
  script_version("2.20");
  script_cvs_date("Date: 2019/10/24 15:35:40");

  script_cve_id("CVE-2015-5304", "CVE-2015-7501");
  script_xref(name:"RHSA", value:"2015:2542");

  script_name(english:"RHEL 6 : JBoss EAP (RHSA-2015:2542)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated jboss-ec2-eap packages that fix two security issues, several
bugs, and add various enhancements are now available for Red Hat JBoss
Enterprise Application Platform 6.4.4 on Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Red Hat JBoss Enterprise Application Platform 6 is a platform for Java
applications based on JBoss Application Server 7.

It was found that the Apache commons-collections library permitted
code execution when deserializing objects involving a specially
constructed chain of classes. A remote attacker could use this flaw to
execute arbitrary code with the permissions of the application using
the commons-collections library. (CVE-2015-7501)

Further information about the commons-collections flaw may be found
at: https://access.redhat.com/solutions/2045023

It was found that JBoss EAP did not properly authorize a user
performing a shut down. A remote user with the Monitor, Deployer, or
Auditor role could use this flaw to shut down the EAP server, which is
an action restricted to admin users. (CVE-2015-5304)

The CVE-2015-5304 issue was discovered by Ladislav Thon of Red Hat
Middleware Quality Engineering.

The jboss-ec2-eap packages provide scripts for Red Hat JBoss
Enterprise Application Platform running on the Amazon Web Services
(AWS) Elastic Compute Cloud (EC2). With this update, the packages have
been updated to ensure compatibility with Red Hat JBoss Enterprise
Application Platform 6.4.5. Documentation for these changes is
available from the link in the References section.

All jboss-ec2-eap users of Red Hat JBoss Enterprise Application
Platform 6.4 on Red Hat Enterprise Linux 6 are advised to upgrade to
these updated packages. The JBoss server process must be restarted for
the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/documentation/en-US/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2015:2542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-7501"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2015-5304"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected jboss-ec2-eap and / or jboss-ec2-eap-samples
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ec2-eap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-ec2-eap-samples");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2015:2542";
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

  if (! (rpm_exists(release:"RHEL6", rpm:"jbossas-welcome-content-eap"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL6", reference:"jboss-ec2-eap-7.5.5-3.Final_redhat_3.ep6.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"jboss-ec2-eap-samples-7.5.5-3.Final_redhat_3.ep6.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jboss-ec2-eap / jboss-ec2-eap-samples");
  }
}
