#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0338. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(46294);
  script_version("1.34");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-0082",
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0093",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0839",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0845",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849"
  );
  script_xref(name:"RHSA", value:"2010:0338");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"RHEL 4 / 5 : java-1.5.0-sun (RHSA-2010:0338)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The java-1.5.0-sun packages as shipped in Red Hat Enterprise Linux 4
Extras and 5 Supplementary contain security flaws and should not be
used.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Sun 1.5.0 Java release includes the Sun Java 5 Runtime Environment
and the Sun Java 5 Software Development Kit.

The java-1.5.0-sun packages are vulnerable to a number of security
flaws and should no longer be used. (CVE-2009-3555, CVE-2010-0082,
CVE-2010-0084, CVE-2010-0085, CVE-2010-0087, CVE-2010-0088,
CVE-2010-0089, CVE-2010-0091, CVE-2010-0092, CVE-2010-0093,
CVE-2010-0094, CVE-2010-0095, CVE-2010-0837, CVE-2010-0838,
CVE-2010-0839, CVE-2010-0840, CVE-2010-0841, CVE-2010-0842,
CVE-2010-0843, CVE-2010-0844, CVE-2010-0845, CVE-2010-0846,
CVE-2010-0847, CVE-2010-0848, CVE-2010-0849)

The Sun Java SE Release family 5.0 reached its End of Service Life on
November 3, 2009. The RHSA-2009:1571 update provided the final
publicly available update of version 5.0 (Update 22). Users interested
in continuing to receive critical fixes for Sun Java SE 5.0 should
contact Oracle :

http://www.sun.com/software/javaforbusiness/index.jsp

An alternative to Sun Java SE 5.0 is the Java 2 Technology Edition of
the IBM Developer Kit for Linux, which is available from the Extras
and Supplementary channels on the Red Hat Network.

Applications capable of using the Java 6 runtime can be migrated to
Java 6 on: OpenJDK (java-1.6.0-openjdk), an open source JDK included
in Red Hat Enterprise Linux 5, since 5.3; the IBM JDK, java-1.6.0-ibm;
or the Sun JDK, java-1.6.0-sun.

This update removes the java-1.5.0-sun packages as they have reached
their End of Service Life.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2009-3555");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0082");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0084");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0085");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0087");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0088");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0089");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0091");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0092");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0093");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0094");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0095");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0837");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0838");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0839");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0840");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0841");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0842");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0843");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0844");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0845");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0846");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0847");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0848");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/cve-2010-0849");
  # http://www.oracle.com/technology/deploy/security/critical-patch-updates/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87fbe7cc");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2010:0338");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.5.0-sun-uninstall package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0849");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java MixerSequencer Object GM_Song Structure Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-uninstall");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  rhsa = "RHSA-2010:0338";
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
  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-uninstall-1.5.0.22-1jpp.3.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-uninstall-1.5.0.22-1jpp.3.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-uninstall-1.5.0.22-1jpp.3.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-uninstall-1.5.0.22-1jpp.3.el5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.5.0-sun-uninstall");
  }
}
