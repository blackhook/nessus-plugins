#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1392. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62636);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0547", "CVE-2012-1531", "CVE-2012-1532", "CVE-2012-1533", "CVE-2012-3143", "CVE-2012-3159", "CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5075", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5089");
  script_xref(name:"RHSA", value:"2012:1392");

  script_name(english:"RHEL 5 / 6 : java-1.6.0-sun (RHSA-2012:1392)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-sun packages that fix several security issues are
now available for Red Hat Enterprise Linux 5 and 6 Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Oracle Java SE version 6 includes the Oracle Java Runtime Environment
and the Oracle Java Software Development Kit.

This update fixes several vulnerabilities in the Oracle Java Runtime
Environment and the Oracle Java Software Development Kit. Further
information about these flaws can be found on the Oracle Java SE
Critical Patch Update Advisory and Oracle Security Alert pages, listed
in the References section. (CVE-2012-0547, CVE-2012-1531,
CVE-2012-1532, CVE-2012-1533, CVE-2012-3143, CVE-2012-3159,
CVE-2012-3216, CVE-2012-4416, CVE-2012-5068, CVE-2012-5069,
CVE-2012-5071, CVE-2012-5072, CVE-2012-5073, CVE-2012-5075,
CVE-2012-5077, CVE-2012-5079, CVE-2012-5081, CVE-2012-5083,
CVE-2012-5084, CVE-2012-5085, CVE-2012-5086, CVE-2012-5089)

All users of java-1.6.0-sun are advised to upgrade to these updated
packages, which provide Oracle Java 6 Update 37. All running instances
of Oracle Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1531.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1532.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1533.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3159.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3216.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4416.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5068.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5069.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5081.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5084.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5085.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5089.html"
  );
  # http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0eb44d4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.oracle.com/technetwork/topics/security/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1392.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Double Quote Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.6.0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-demo-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-devel-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-jdbc-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-plugin-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.6.0-sun-src-1.6.0.37-1jpp.1.el5_8")) flag++;

if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.37-1jpp.1.el5_8")) flag++;


if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-demo-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-demo-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-devel-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-devel-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-jdbc-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-jdbc-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-plugin-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-plugin-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.6.0-sun-src-1.6.0.37-1jpp.1.el6_3")) flag++;

if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.6.0-sun-src-1.6.0.37-1jpp.1.el6_3")) flag++;



if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-sun / java-1.6.0-sun-demo / java-1.6.0-sun-devel / etc");
}
