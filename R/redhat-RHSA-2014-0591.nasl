#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0591. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74300);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-0107");
  script_bugtraq_id(66397);
  script_xref(name:"RHSA", value:"2014:0591");

  script_name(english:"RHEL 5 / 6 : JBoss EAP (RHSA-2014:0591)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages for JBoss Enterprise Application Platform 5.2.0 which
fix one security issue and one bug are now available for Red Hat
Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
Important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

JBoss Enterprise Application Platform is a platform for Java
applications, which integrates the JBoss Application Server with JBoss
Hibernate and JBoss Seam.

It was found that the secure processing feature of Xalan-Java had
insufficient restrictions defined for certain properties and features.
A remote attacker able to provide Extensible Stylesheet Language
Transformations (XSLT) content to be processed by an application using
Xalan-Java could use this flaw to bypass the intended constraints of
the secure processing feature. Depending on the components available
in the classpath, this could lead to arbitrary remote code execution
in the context of the application server running the application that
uses Xalan-Java. (CVE-2014-0107)

This update also fixes the following bug :

It was observed that when using the Transfomer to convert a
StreamSource to DOMResult, the performance of the conversion degraded
as the size of the character data increased. For example, converting a
50 MB XML BLOB would take a very long time to finish. This issue has
been resolved in this release by adjusting both the SAX2DOM and
DOMBuilder classes to handle larger inputs more efficiently.
(JBPAPP-10991)

All users of JBoss Enterprise Application Platform 5.2.0 on Red Hat
Enterprise Linux 4, 5, and 6 are advised to upgrade to these updated
packages. The JBoss server process must be restarted for the update to
take effect."
  );
  # https://issues.jboss.org/browse/JBPAPP-10991
  script_set_attribute(
    attribute:"see_also",
    value:"https://issues.jboss.org/browse/JBPAPP-10991?_sscc=t"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0107"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xalan-j2 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0591";
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

  if (! (rpm_exists(release:"RHEL5", rpm:"xalan-j2-") || rpm_exists(release:"RHEL6", rpm:"xalan-j2-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "JBoss EAP");

  if (rpm_check(release:"RHEL5", reference:"xalan-j2-2.7.1-12_patch_08.ep5.el5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"xalan-j2-2.7.1-12_patch_08.ep5.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xalan-j2");
  }
}
