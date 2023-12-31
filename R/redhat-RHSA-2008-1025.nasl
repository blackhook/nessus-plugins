#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:1025. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40732);
  script_version("1.31");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-2086", "CVE-2008-5339", "CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5343", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5346", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5355", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360");
  script_bugtraq_id(32620, 32892);
  script_xref(name:"RHSA", value:"2008:1025");

  script_name(english:"RHEL 4 / 5 : java-1.5.0-sun (RHSA-2008:1025)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.5.0-sun packages that correct several security issues
are now available for Red Hat Enterprise Linux 4 Extras and 5
Supplementary.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The Java Runtime Environment (JRE) contains the software and tools
that users need to run applets and applications written using the Java
programming language.

A vulnerability was found in in Java Web Start. If a user visits a
malicious website, an attacker could misuse this flaw to execute
arbitrary code. (CVE-2008-2086)

Additionally, these packages fix several other vulnerabilities. These
are summarized in the 'Advance notification of Security Updates for
Java SE' from Sun Microsystems.

Users of java-1.5.0-sun should upgrade to these updated packages,
which correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-2086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-5360"
  );
  # http://blogs.sun.com/security/entry/advance_notification_of_security_updates3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8d7aabf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2008:1025"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119, 189, 200, 264, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/04");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:1025";
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
  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-1.5.0.17-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-1.5.0.17-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-demo-1.5.0.17-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-demo-1.5.0.17-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-devel-1.5.0.17-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-devel-1.5.0.17-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-jdbc-1.5.0.17-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-jdbc-1.5.0.17-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-plugin-1.5.0.17-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-src-1.5.0.17-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-src-1.5.0.17-1jpp.2.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-1.5.0.17-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-1.5.0.17-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-demo-1.5.0.17-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-demo-1.5.0.17-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-devel-1.5.0.17-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-devel-1.5.0.17-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-jdbc-1.5.0.17-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-jdbc-1.5.0.17-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-plugin-1.5.0.17-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-src-1.5.0.17-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-src-1.5.0.17-1jpp.2.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.5.0-sun / java-1.5.0-sun-demo / java-1.5.0-sun-devel / etc");
  }
}
