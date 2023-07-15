#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:4113. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(131919);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/12");

  script_cve_id("CVE-2019-17631", "CVE-2019-2945", "CVE-2019-2962", "CVE-2019-2964", "CVE-2019-2973", "CVE-2019-2975", "CVE-2019-2978", "CVE-2019-2981", "CVE-2019-2983", "CVE-2019-2988", "CVE-2019-2989", "CVE-2019-2992", "CVE-2019-2996", "CVE-2019-2999");
  script_xref(name:"RHSA", value:"2019:4113");

  script_name(english:"RHEL 6 : java-1.8.0-ibm (RHSA-2019:4113)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for java-1.8.0-ibm is now available for Red Hat Enterprise
Linux 6 Supplementary.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

IBM Java SE version 8 includes the IBM Java Runtime Environment and
the IBM Java Software Development Kit.

This update upgrades IBM Java SE 8 to version 8 SR6.

Security Fix(es) :

* OpenJDK: Unexpected exception thrown during regular expression
processing in Nashorn (Scripting, 8223518) (CVE-2019-2975)

* OpenJDK: Incorrect handling of nested jar: URLs in Jar URL handler
(Networking, 8223892) (CVE-2019-2978)

* OpenJDK: Incorrect handling of HTTP proxy responses in
HttpURLConnection (Networking, 8225298) (CVE-2019-2989)

* Oracle JDK: unspecified vulnerability fixed in 8u221 (Deployment)
(CVE-2019-2996)

* IBM JDK: Unrestricted access to diagnostic operations
(CVE-2019-17631)

* OpenJDK: Missing restrictions on use of custom SocketImpl
(Networking, 8218573) (CVE-2019-2945)

* OpenJDK: NULL pointer dereference in DrawGlyphList (2D, 8222690)
(CVE-2019-2962)

* OpenJDK: Unexpected exception thrown by Pattern processing crafted
regular expression (Concurrency, 8222684) (CVE-2019-2964)

* OpenJDK: Unexpected exception thrown by XPathParser processing
crafted XPath expression (JAXP, 8223505) (CVE-2019-2973)

* OpenJDK: Unexpected exception thrown by XPath processing crafted
XPath expression (JAXP, 8224532) (CVE-2019-2981)

* OpenJDK: Unexpected exception thrown during Font object
deserialization (Serialization, 8224915) (CVE-2019-2983)

* OpenJDK: Integer overflow in bounds check in SunGraphics2D (2D,
8225292) (CVE-2019-2988)

* OpenJDK: Excessive memory allocation in CMap when reading TrueType
font (2D, 8225597) (CVE-2019-2992)

* OpenJDK: Insufficient filtering of HTML event attributes in Javadoc
(Javadoc, 8226765) (CVE-2019-2999)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:4113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-2999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-17631"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.8.0-ibm-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
  rhsa = "RHSA-2019:4113";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-demo-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-demo-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-demo-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-devel-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-devel-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-devel-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-jdbc-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-jdbc-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-jdbc-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-plugin-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-plugin-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.8.0-ibm-src-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"java-1.8.0-ibm-src-1.8.0.6.0-1jpp.1.el6_10")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.8.0-ibm-src-1.8.0.6.0-1jpp.1.el6_10")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-ibm / java-1.8.0-ibm-demo / java-1.8.0-ibm-devel / etc");
  }
}
