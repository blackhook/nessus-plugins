#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0186. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40717);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196");
  script_bugtraq_id(28083, 28125);
  script_xref(name:"RHSA", value:"2008:0186");

  script_name(english:"RHEL 4 / 5 : java-1.5.0-sun (RHSA-2008:0186)");
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

Flaws in the JRE allowed an untrusted application or applet to elevate
its privileges. This could be exploited by a remote attacker to access
local files or execute local applications accessible to the user
running the JRE (CVE-2008-1185, CVE-2008-1186)

A flaw was found in the Java XSLT processing classes. An untrusted
application or applet could cause a denial of service, or execute
arbitrary code with the permissions of the user running the JRE.
(CVE-2008-1187)

Several buffer overflow flaws were found in Java Web Start (JWS). An
untrusted JNLP application could access local files or execute local
applications accessible to the user running the JRE. (CVE-2008-1188,
CVE-2008-1189, CVE-2008-1190, CVE-2008-1191, CVE-2008-1196)

A flaw was found in the Java Plug-in. A remote attacker could bypass
the same origin policy, executing arbitrary code with the permissions
of the user running the JRE. (CVE-2008-1192)

A flaw was found in the JRE image parsing libraries. An untrusted
application or applet could cause a denial of service, or possible
execute arbitrary code with the permissions of the user running the
JRE. (CVE-2008-1193)

A flaw was found in the JRE color management library. An untrusted
application or applet could trigger a denial of service (JVM crash).
(CVE-2008-1194)

The JRE allowed untrusted JavaScript code to create local network
connections by the use of Java APIs. A remote attacker could use these
flaws to access local network services. (CVE-2008-1195)

This update also fixes an issue where the Java Plug-in is not
available for browser use after successful installation.

Users of java-1.5.0-sun should upgrade to these updated packages,
which correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2008-1196"
  );
  # http://sunsolve.sun.com/search/document.do?assetkey=1-66-233321-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ecc5fe32"
  );
  # http://sunsolve.sun.com/search/document.do?assetkey=1-66-233322-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d0f90a5"
  );
  # http://sunsolve.sun.com/search/document.do?assetkey=1-66-233323-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1259b9b1"
  );
  # http://sunsolve.sun.com/search/document.do?assetkey=1-66-233324-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d8d3953"
  );
  # http://sunsolve.sun.com/search/document.do?assetkey=1-66-233325-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e329ebd"
  );
  # http://sunsolve.sun.com/search/document.do?assetkey=1-66-233326-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4755491e"
  );
  # http://sunsolve.sun.com/search/document.do?assetkey=1-66-233327-1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f802ba78"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2008:0186"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.5.0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/06");
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
  rhsa = "RHSA-2008:0186";
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
  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-1.5.0.15-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-1.5.0.15-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-demo-1.5.0.15-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-demo-1.5.0.15-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-devel-1.5.0.15-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-devel-1.5.0.15-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-jdbc-1.5.0.15-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-jdbc-1.5.0.15-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-plugin-1.5.0.15-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"i586", reference:"java-1.5.0-sun-src-1.5.0.15-1jpp.2.el4")) flag++;

  if (rpm_check(release:"RHEL4", cpu:"x86_64", reference:"java-1.5.0-sun-src-1.5.0.15-1jpp.2.el4")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-1.5.0.15-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-1.5.0.15-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-demo-1.5.0.15-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-demo-1.5.0.15-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-devel-1.5.0.15-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-devel-1.5.0.15-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-jdbc-1.5.0.15-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-jdbc-1.5.0.15-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-plugin-1.5.0.15-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i586", reference:"java-1.5.0-sun-src-1.5.0.15-1jpp.2.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"java-1.5.0-sun-src-1.5.0.15-1jpp.2.el5")) flag++;


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
