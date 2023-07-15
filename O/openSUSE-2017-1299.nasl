#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1299.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104765);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2017-12617", "CVE-2017-5664", "CVE-2017-7674");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-2017-1299)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for tomcat fixes the following issues :

Security issues fixed :

  - CVE-2017-5664: A problem in handling error pages was
    fixed, to avoid potential file overwrites during error
    page handling. (bsc#1042910).

  - CVE-2017-7674: A CORS Filter issue could lead to client
    and server side cache poisoning (bsc#1053352)

  - CVE-2017-12617: A remote code execution possibility via
    JSP Upload was fixed (bsc#1059554)

Non security bugs fixed :

  - Fix tomcat-digest classpath error (bsc#977410) 

  - Fix packaged /etc/alternatives symlinks for api libs
    that caused rpm -V to report link mismatch (bsc#1019016)

This update was imported from the SUSE:SLE-12-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053352");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977410");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat for Windows HTTP PUT Method File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"tomcat-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-admin-webapps-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-docs-webapp-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-el-3_0-api-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-embed-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-javadoc-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-jsp-2_3-api-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-jsvc-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-lib-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-servlet-3_1-api-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-webapps-8.0.43-6.13.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-8.0.43-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-admin-webapps-8.0.43-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-docs-webapp-8.0.43-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-el-3_0-api-8.0.43-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-embed-8.0.43-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-javadoc-8.0.43-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-jsp-2_3-api-8.0.43-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-jsvc-8.0.43-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-lib-8.0.43-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-servlet-3_1-api-8.0.43-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-webapps-8.0.43-9.1") ) flag++;

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
