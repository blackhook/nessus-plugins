#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1799.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142186);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-13943");
  script_xref(name:"IAVA", value:"2020-A-0465-S");

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-2020-1799)");
  script_summary(english:"Check for the openSUSE-2020-1799 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for tomcat fixes the following issues :

  - CVE-2020-13943: Fixed HTTP/2 Request mix-up
    (bsc#1177582)

This update was imported from the SUSE:SLE-15-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177582"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13943");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"tomcat-9.0.36-lp152.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tomcat-admin-webapps-9.0.36-lp152.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tomcat-docs-webapp-9.0.36-lp152.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tomcat-el-3_0-api-9.0.36-lp152.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tomcat-embed-9.0.36-lp152.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tomcat-javadoc-9.0.36-lp152.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tomcat-jsp-2_3-api-9.0.36-lp152.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tomcat-jsvc-9.0.36-lp152.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tomcat-lib-9.0.36-lp152.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tomcat-servlet-4_0-api-9.0.36-lp152.2.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tomcat-webapps-9.0.36-lp152.2.10.1") ) flag++;

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
