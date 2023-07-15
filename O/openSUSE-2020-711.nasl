#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-711.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(136889);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-9484");
  script_xref(name:"IAVA", value:"2020-A-0225-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-2020-711)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for tomcat fixes the following issues :

  - Update to Tomcat 9.0.35. See changelog at
    http://tomcat.apache.org/tomcat-9.0-doc/changelog.html#T
    omcat_9.0.35_(markt)

  - CVE-2020-9484 (bsc#1171928) Apache Tomcat Remote Code
    Execution via session persistence

    If an attacker was able to control the contents and name
    of a file on a server configured to use the
    PersistenceManager, then the attacker could have
    triggered a remote code execution via deserialization of
    the file under their control.

This update was imported from the SUSE:SLE-15-SP1:Update update
project.");
  # http://tomcat.apache.org/tomcat-9.0-doc/changelog.html#Tomcat_9.0.35_(markt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa77797d");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171928");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9484");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/26");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-servlet-4_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"tomcat-9.0.35-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tomcat-admin-webapps-9.0.35-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tomcat-docs-webapp-9.0.35-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tomcat-el-3_0-api-9.0.35-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tomcat-embed-9.0.35-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tomcat-javadoc-9.0.35-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tomcat-jsp-2_3-api-9.0.35-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tomcat-jsvc-9.0.35-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tomcat-lib-9.0.35-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tomcat-servlet-4_0-api-9.0.35-lp151.3.18.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tomcat-webapps-9.0.35-lp151.3.18.1") ) flag++;

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
