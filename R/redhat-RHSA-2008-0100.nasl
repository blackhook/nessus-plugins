#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0100. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40712);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-2788", "CVE-2007-2789", "CVE-2007-3698", "CVE-2007-4381", "CVE-2007-5232", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5273");
  script_bugtraq_id(24004, 24846, 25340, 25918);
  script_xref(name:"RHSA", value:"2008:0100");

  script_name(english:"RHEL 3 / 4 / 5 : java-1.4.2-bea (RHSA-2008:0100)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.4.2-bea packages that correct several security issues
and add enhancements are now available for Red Hat Enterprise Linux 3
Extras, Red Hat Enterprise Linux 4 Extras, and Red Hat Enterprise
Linux 5 Supplementary.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The BEA WebLogic JRockit 1.4.2_16 JRE and SDK contains BEA WebLogic
JRockit Virtual Machine 1.4.2_16 and is certified for the Java 2
Platform, Standard Edition, v1.4.2.

A buffer overflow in the Java Runtime Environment image handling code
was found. If an attacker could induce a server application to process
a specially crafted image file, the attacker could potentially cause a
denial-of-service or execute arbitrary code as the user running the
Java Virtual Machine. (CVE-2007-2788, CVE-2007-2789)

A denial of service flaw was found in the way the JSSE component
processed SSL/TLS handshake requests. A remote attacker able to
connect to a JSSE enabled service could send a specially crafted
handshake which would cause the Java Runtime Environment to stop
responding to future requests. (CVE-2007-3698)

A flaw was found in the way the Java Runtime Environment processed
font data. An applet viewed via the 'appletviewer' application could
elevate its privileges, allowing the applet to perform actions with
the same permissions as the user running the 'appletviewer'
application. The same flaw could, potentially, crash a server
application which processed untrusted font information from a third
party. (CVE-2007-4381)

A flaw in the applet caching mechanism of the Java Runtime Environment
(JRE) did not correctly process the creation of network connections. A
remote attacker could use this flaw to create connections to services
on machines other than the one that the applet was downloaded from.
(CVE-2007-5232)

Untrusted Java Applets were able to drag and drop files to a desktop
application. A user-assisted remote attacker could use this flaw to
move or copy arbitrary files. (CVE-2007-5239)

The Java Runtime Environment (JRE) allowed untrusted Java Applets or
applications to display over-sized windows. This could be used by
remote attackers to hide security warning banners. (CVE-2007-5240)

Unsigned Java Applets communicating via a HTTP proxy could allow a
remote attacker to violate the Java security model. A cached,
malicious Applet could create network connections to services on other
machines. (CVE-2007-5273)

Please note: the vulnerabilities noted above concerned with applets
can only be triggered in java-1.4.2-bea by calling the 'appletviewer'
application.

All users of java-1.4.2-bea should upgrade to these updated packages,
which contain the BEA WebLogic JRockit 1.4.2_16 release which resolves
these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-2788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-2789"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-3698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-4381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-5232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-5239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-5240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2007-5273"
  );
  # http://dev2dev.bea.com/pub/advisory/249
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?659e0990"
  );
  # http://dev2dev.bea.com/pub/advisory/248
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e16bf0b7"
  );
  # http://dev2dev.bea.com/pub/advisory/272
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dd1a2b1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2008:0100"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-bea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-bea-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-bea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-bea-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-bea-missioncontrol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.4.2-bea-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0100";
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
  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"java-1.4.2-bea-1.4.2.16-1jpp.1.el3")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"java-1.4.2-bea-devel-1.4.2.16-1jpp.1.el3")) flag++;

  if (rpm_check(release:"RHEL3", cpu:"i686", reference:"java-1.4.2-bea-jdbc-1.4.2.16-1jpp.1.el3")) flag++;


  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.4.2-bea-1.4.2.16-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.4.2-bea-devel-1.4.2.16-1jpp.1.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i686", reference:"java-1.4.2-bea-jdbc-1.4.2.16-1jpp.1.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.4.2-bea-1.4.2.16-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.4.2-bea-demo-1.4.2.16-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.4.2-bea-devel-1.4.2.16-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.4.2-bea-jdbc-1.4.2.16-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.4.2-bea-missioncontrol-1.4.2.16-1jpp.1.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i686", reference:"java-1.4.2-bea-src-1.4.2.16-1jpp.1.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.4.2-bea / java-1.4.2-bea-demo / java-1.4.2-bea-devel / etc");
  }
}
