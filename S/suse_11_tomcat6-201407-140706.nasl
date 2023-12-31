#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77197);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-3544", "CVE-2013-4322", "CVE-2014-0096", "CVE-2014-0099", "CVE-2014-0119");

  script_name(english:"SuSE 11.3 Security Update : tomcat6 (SAT Patch Number 9487)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tomcat has been updated to version 6.0.41, which brings security and
bug fixes.

The following security fixes have been fixed :

  - A XXE vulnerability via user-supplied XSLTs.
    (CVE-2014-0096)

  - Request smuggling via malicious content length header.
    (CVE-2014-0099)

  - A XML parser hijack by malicious web application. Bugs
    fixed:. (CVE-2014-0119)

  - Socket bind fails on tomcat startup when using apr
    (IPV6). (bnc#881700)

  - classpath for org/apache/juli/logging/LogFactory
    (bnc#844689)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=844689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3544.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4322.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0099.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0119.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9487.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libtcnative-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-jsp-2_1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-servlet-2_5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLES11", sp:3, reference:"libtcnative-1-0-1.3.3-12.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"tomcat6-6.0.41-0.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"tomcat6-admin-webapps-6.0.41-0.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"tomcat6-docs-webapp-6.0.41-0.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"tomcat6-javadoc-6.0.41-0.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"tomcat6-jsp-2_1-api-6.0.41-0.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"tomcat6-lib-6.0.41-0.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"tomcat6-servlet-2_5-api-6.0.41-0.43.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"tomcat6-webapps-6.0.41-0.43.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
