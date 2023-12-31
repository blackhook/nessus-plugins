#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1385. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62614);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5075", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5089");
  script_xref(name:"RHSA", value:"2012:1385");

  script_name(english:"RHEL 5 : java-1.6.0-openjdk (RHSA-2012:1385) (ROBOT)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix several security issues
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit.

Multiple improper permission check issues were discovered in the
Beans, Swing, and JMX components in OpenJDK. An untrusted Java
application or applet could use these flaws to bypass Java sandbox
restrictions. (CVE-2012-5086, CVE-2012-5084, CVE-2012-5089)

Multiple improper permission check issues were discovered in the
Scripting, JMX, Concurrency, Libraries, and Security components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2012-5068,
CVE-2012-5071, CVE-2012-5069, CVE-2012-5073, CVE-2012-5072)

It was discovered that java.util.ServiceLoader could create an
instance of an incompatible class while performing provider lookup. An
untrusted Java application or applet could use this flaw to bypass
certain Java sandbox restrictions. (CVE-2012-5079)

It was discovered that the Java Secure Socket Extension (JSSE) SSL/TLS
implementation did not properly handle handshake records containing an
overly large data length value. An unauthenticated, remote attacker
could possibly use this flaw to cause an SSL/TLS server to terminate
with an exception. (CVE-2012-5081)

It was discovered that the JMX component in OpenJDK could perform
certain actions in an insecure manner. An untrusted Java application
or applet could possibly use this flaw to disclose sensitive
information. (CVE-2012-5075)

A bug in the Java HotSpot Virtual Machine optimization code could
cause it to not perform array initialization in certain cases. An
untrusted Java application or applet could use this flaw to disclose
portions of the virtual machine's memory. (CVE-2012-4416)

It was discovered that the SecureRandom class did not properly protect
against the creation of multiple seeders. An untrusted Java
application or applet could possibly use this flaw to disclose
sensitive information. (CVE-2012-5077)

It was discovered that the java.io.FilePermission class exposed the
hash code of the canonicalized path name. An untrusted Java
application or applet could possibly use this flaw to determine
certain system paths, such as the current working directory.
(CVE-2012-3216)

This update disables Gopher protocol support in the java.net package
by default. Gopher support can be enabled by setting the newly
introduced property, 'jdk.net.registerGopherProtocol', to true.
(CVE-2012-5085)

This erratum also upgrades the OpenJDK package to IcedTea6 1.10.10.
Refer to the NEWS file, linked to in the References, for further
information.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://icedtea.classpath.org/hg/release/icedtea6-1.10/file/icedtea6-1.10.10
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d63b729c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.oracle.com/technetwork/topics/security/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2012:1385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-4416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-3216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2012-5077"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/17");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1385";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.28.1.10.10.el5_8")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.28.1.10.10.el5_8")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-debuginfo / etc");
  }
}
