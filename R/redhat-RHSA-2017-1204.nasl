#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1204. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100091);
  script_version("3.13");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_xref(name:"RHSA", value:"2017:1204");

  script_name(english:"RHEL 6 / 7 : java-1.7.0-openjdk (RHSA-2017:1204)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.7.0-openjdk is now available for Red Hat
Enterprise Linux 6 and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The java-1.7.0-openjdk packages provide the OpenJDK 7 Java Runtime
Environment and the OpenJDK 7 Java Software Development Kit.

Security Fix(es) :

* An untrusted library search path flaw was found in the JCE component
of OpenJDK. A local attacker could possibly use this flaw to cause a
Java application using JCE to load an attacker-controlled library and
hence escalate their privileges. (CVE-2017-3511)

* It was found that the JAXP component of OpenJDK failed to correctly
enforce parse tree size limits when parsing XML document. An attacker
able to make a Java application parse a specially crafted XML document
could use this flaw to make it consume an excessive amount of CPU and
memory. (CVE-2017-3526)

* It was discovered that the HTTP client implementation in the
Networking component of OpenJDK could cache and re-use an NTLM
authenticated connection in a different security context. A remote
attacker could possibly use this flaw to make a Java application
perform HTTP requests authenticated with credentials of a different
user. (CVE-2017-3509)

Note: This update adds support for the 'jdk.ntlm.cache' system
property which, when set to false, prevents caching of NTLM
connections and authentications and hence prevents this issue.
However, caching remains enabled by default.

* It was discovered that the Security component of OpenJDK did not
allow users to restrict the set of algorithms allowed for Jar
integrity verification. This flaw could allow an attacker to modify
content of the Jar file that used weak signing key or hash algorithm.
(CVE-2017-3539)

Note: This updates extends the fix for CVE-2016-5542 released as part
of the RHSA-2016:2658 erratum to no longer allow the MD5 hash
algorithm during the Jar integrity verification by adding it to the
jdk.jar.disabledAlgorithms security property.

* Newline injection flaws were discovered in FTP and SMTP client
implementations in the Networking component in OpenJDK. A remote
attacker could possibly use these flaws to manipulate FTP or SMTP
connections established by a Java application. (CVE-2017-3533,
CVE-2017-3544)"
  );
  # https://rhn.redhat.com/errata/RHSA-2016-2658.html
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2016:2658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:1204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-3544"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/10");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1204";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-1.7.0.141-2.6.10.1.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.141-2.6.10.1.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.141-2.6.10.1.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.141-2.6.10.1.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-demo-1.7.0.141-2.6.10.1.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.141-2.6.10.1.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-devel-1.7.0.141-2.6.10.1.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.141-2.6.10.1.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.141-2.6.10.1.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-openjdk-src-1.7.0.141-2.6.10.1.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.141-2.6.10.1.el6_9")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-accessibility-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-demo-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-devel-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-headless-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", reference:"java-1.7.0-openjdk-javadoc-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"java-1.7.0-openjdk-src-1.7.0.141-2.6.10.1.el7_3")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.141-2.6.10.1.el7_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-accessibility / etc");
  }
}
