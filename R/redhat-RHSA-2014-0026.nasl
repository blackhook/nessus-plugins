#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0026. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71962);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5893", "CVE-2013-5896", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376", "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0428");
  script_bugtraq_id(64863, 64894, 64907, 64914, 64918, 64921, 64922, 64924, 64926, 64927, 64930, 64933, 64935, 64937);
  script_xref(name:"RHSA", value:"2014:0026");

  script_name(english:"RHEL 6 : java-1.7.0-openjdk (RHSA-2014:0026)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-openjdk packages that fix various security issues
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 7 Java Runtime Environment and the
OpenJDK 7 Software Development Kit.

An input validation flaw was discovered in the font layout engine in
the 2D component. A specially crafted font file could trigger Java
Virtual Machine memory corruption when processed. An untrusted Java
application or applet could possibly use this flaw to bypass Java
sandbox restrictions. (CVE-2013-5907)

Multiple improper permission check issues were discovered in the
CORBA, JNDI, and Libraries components in OpenJDK. An untrusted Java
application or applet could use these flaws to bypass Java sandbox
restrictions. (CVE-2014-0428, CVE-2014-0422, CVE-2013-5893)

Multiple improper permission check issues were discovered in the
Serviceability, Security, CORBA, JAAS, JAXP, and Networking components
in OpenJDK. An untrusted Java application or applet could use these
flaws to bypass certain Java sandbox restrictions. (CVE-2014-0373,
CVE-2013-5878, CVE-2013-5910, CVE-2013-5896, CVE-2013-5884,
CVE-2014-0416, CVE-2014-0376, CVE-2014-0368)

It was discovered that the Beans component did not restrict processing
of XML external entities. This flaw could cause a Java application
using Beans to leak sensitive information, or affect application
availability. (CVE-2014-0423)

It was discovered that the JSSE component could leak timing
information during the TLS/SSL handshake. This could possibly lead to
disclosure of information about the used encryption keys.
(CVE-2014-0411)

Note: The java-1.7.0-openjdk package shipped with Red Hat Enterprise
Linux 6.5 via RHBA-2013:1611 replaced 'java7' with 'java' in the
provides list. This update re-adds 'java7' to the provides list to
maintain backwards compatibility with releases prior to Red Hat
Enterprise Linux 6.5.

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

All users of java-1.7.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17c46362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2014:0026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-5896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2014-0423"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/15");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0026";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-1.7.0.51-2.4.4.1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.51-2.4.4.1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.51-2.4.4.1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.51-2.4.4.1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-demo-1.7.0.51-2.4.4.1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.51-2.4.4.1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-devel-1.7.0.51-2.4.4.1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.51-2.4.4.1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.51-2.4.4.1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-src-1.7.0.51-2.4.4.1.el6_5")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.51-2.4.4.1.el6_5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-debuginfo / etc");
  }
}
