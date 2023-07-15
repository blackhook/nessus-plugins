#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-325.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108742);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15706", "CVE-2018-1304", "CVE-2018-1305");

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-2018-325)");
  script_summary(english:"Check for the openSUSE-2018-325 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tomcat fixes the following issues :

Security issues fixed :

  - CVE-2018-1305: Fixed late application of security
    constraints that can lead to resource exposure for
    unauthorised users (bsc#1082481).

  - CVE-2018-1304: Fixed incorrect handling of empty string
    URL in security constraints that can lead to unitended
    exposure of resources (bsc#1082480).

  - CVE-2017-15706: Fixed incorrect documentation of CGI
    Servlet search algorithm that may lead to
    misconfiguration (bsc#1078677).

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1078677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1082481"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-el-3_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-jsp-2_3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-servlet-3_1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"tomcat-8.0.50-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-admin-webapps-8.0.50-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-docs-webapp-8.0.50-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-el-3_0-api-8.0.50-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-embed-8.0.50-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-javadoc-8.0.50-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-jsp-2_3-api-8.0.50-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-jsvc-8.0.50-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-lib-8.0.50-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-servlet-3_1-api-8.0.50-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-webapps-8.0.50-12.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
