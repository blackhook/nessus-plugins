#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1456.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(95791);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/14");

  script_cve_id(
    "CVE-2016-0762",
    "CVE-2016-5018",
    "CVE-2016-6794",
    "CVE-2016-6796",
    "CVE-2016-6797",
    "CVE-2016-6816",
    "CVE-2016-8735"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/06/02");

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-2016-1456)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for tomcat fixes the following issues :

Feature changes :

The embedded Apache Commons DBCP component was updated to version 2.0.
(bsc#1010893 fate#321029)

Security fixes :

  - CVE-2016-0762: Realm Timing Attack (bsc#1007854)

  - CVE-2016-5018: Security Manager Bypass (bsc#1007855)

  - CVE-2016-6794: System Property Disclosure (bsc#1007857)

  - CVE-2016-6796: Security Manager Bypass (bsc#1007858)

  - CVE-2016-6797: Unrestricted Access to Global Resources
    (bsc#1007853)

  - CVE-2016-8735: Remote code execution vulnerability in
    JmxRemoteLifecycleListener (bsc#1011805)

  - CVE-2016-6816: HTTP Request smuggling vulnerability due
    to permitting invalid character in HTTP requests
    (bsc#1011812)

Bug fixes :

  - Enabled optional setenv.sh script. See section '(3.4)
    Using the 'setenv' script' in
    http://tomcat.apache.org/tomcat-8.0-doc/RUNNING.txt.
    (bsc#1002639)

This update supplies the new packages apache-commons-pool2 and
apache-commons-dbcp in version 2 to allow tomcat to use the DBCP 2.0
interface.

This update was imported from the SUSE:SLE-12-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/tomcat-8.0-doc/RUNNING.txt.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007853");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007854");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007855");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010893");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011805");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011812");
  script_set_attribute(attribute:"see_also", value:"https://features.opensuse.org/");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache-commons-dbcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache-commons-dbcp-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache-commons-pool2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache-commons-pool2-javadoc");
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
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"apache-commons-dbcp-2.1.1-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apache-commons-dbcp-javadoc-2.1.1-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apache-commons-pool2-2.4.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"apache-commons-pool2-javadoc-2.4.2-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-8.0.36-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-admin-webapps-8.0.36-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-docs-webapp-8.0.36-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-el-3_0-api-8.0.36-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-embed-8.0.36-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-javadoc-8.0.36-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-jsp-2_3-api-8.0.36-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-jsvc-8.0.36-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-lib-8.0.36-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-servlet-3_1-api-8.0.36-4.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"tomcat-webapps-8.0.36-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache-commons-dbcp / apache-commons-dbcp-javadoc / etc");
}
