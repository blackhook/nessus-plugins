#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1463. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109908);
  script_version("1.5");
  script_cvs_date("Date: 2019/10/24 15:35:44");

  script_cve_id("CVE-2018-1417", "CVE-2018-2579", "CVE-2018-2581", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2627", "CVE-2018-2629", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2638", "CVE-2018-2639", "CVE-2018-2641", "CVE-2018-2657", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");
  script_xref(name:"RHSA", value:"2018:1463");

  script_name(english:"RHEL 6 : java-1.8.0-ibm (RHSA-2018:1463)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.8.0-ibm is now available for Red Hat Satellite
5.8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

IBM Java SE version 8 includes the IBM Java Runtime Environment and
the IBM Java Software Development Kit.

This update upgrades IBM Java SE 8 to version 8 SR5-FP10.

Security Fix(es) :

* IBM JDK: J9 JVM allows untrusted code running under a security
manager to elevate its privileges (CVE-2018-1417)

* Oracle JDK: unspecified vulnerability fixed in 8u161 and 9.0.4
(Deployment) (CVE-2018-2638)

* Oracle JDK: unspecified vulnerability fixed in 8u161 and 9.0.4
(Deployment) (CVE-2018-2639)

* OpenJDK: insufficient validation of the invokeinterface instruction
(Hotspot, 8174962) (CVE-2018-2582)

* Oracle JDK: unspecified vulnerability fixed in 8u161 and 9.0.4
(Installer) (CVE-2018-2627)

* OpenJDK: LDAPCertStore insecure handling of LDAP referrals (JNDI,
8186606) (CVE-2018-2633)

* OpenJDK: use of global credentials for HTTP/SPNEGO (JGSS, 8186600)
(CVE-2018-2634)

* OpenJDK: SingleEntryRegistry incorrect setup of deserialization
filter (JMX, 8186998) (CVE-2018-2637)

* OpenJDK: GTK library loading use-after-free (AWT, 8185325)
(CVE-2018-2641)

* Oracle JDK: unspecified vulnerability fixed in 7u171, 8u161, and
9.0.4 (JavaFX) (CVE-2018-2581)

* OpenJDK: LdapLoginModule insufficient username encoding in LDAP
query (LDAP, 8178449) (CVE-2018-2588)

* OpenJDK: DnsClient missing source port randomization (JNDI, 8182125)
(CVE-2018-2599)

* OpenJDK: loading of classes from untrusted locations (I18n, 8182601)
(CVE-2018-2602)

* OpenJDK: DerValue unbounded memory allocation (Libraries, 8182387)
(CVE-2018-2603)

* OpenJDK: insufficient strength of key agreement (JCE, 8185292)
(CVE-2018-2618)

* OpenJDK: GSS context use-after-free (JGSS, 8186212) (CVE-2018-2629)

* Oracle JDK: unspecified vulnerability fixed in 6u181 and 7u171
(Serialization) (CVE-2018-2657)

* OpenJDK: ArrayBlockingQueue deserialization to an inconsistent state
(Libraries, 8189284) (CVE-2018-2663)

* OpenJDK: unbounded memory allocation during deserialization (AWT,
8190289) (CVE-2018-2677)

* OpenJDK: unbounded memory allocation in BasicAttributes
deserialization (JNDI, 8191142) (CVE-2018-2678)

* OpenJDK: unsynchronized access to encryption key data (Libraries,
8172525) (CVE-2018-2579)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2018:1463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-1417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-2678"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected java-1.8.0-ibm and / or java-1.8.0-ibm-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2018:1463";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-1.8.0.5.10-1jpp.1.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-1.8.0.5.10-1jpp.1.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-devel-1.8.0.5.10-1jpp.1.el6_9")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-devel-1.8.0.5.10-1jpp.1.el6_9")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-ibm / java-1.8.0-ibm-devel");
  }
}
