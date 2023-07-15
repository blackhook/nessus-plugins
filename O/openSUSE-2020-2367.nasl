#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2367.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145385);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-17521");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE Security Update : groovy (openSUSE-2020-2367)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for groovy fixes the following issues :

&#9; - groovy was updated to 2.4.21

  - CVE-2020-17521: Fixed an information disclosure
    vulnerability (bsc#1179729).

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179729");
  script_set_attribute(attribute:"solution", value:
"Update the affected groovy packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-ant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-docgenerator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-groovydoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-groovysh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-jsr223");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-nio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-servlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-swing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-testng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:groovy-xml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.2", reference:"groovy-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-ant-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-bsf-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-console-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-docgenerator-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-groovydoc-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-groovysh-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-jmx-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-json-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-jsr223-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-lib-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-nio-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-servlet-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-sql-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-swing-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-templates-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-test-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-testng-2.4.21-lp152.2.3.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"groovy-xml-2.4.21-lp152.2.3.2") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "groovy / groovy-ant / groovy-bsf / groovy-console / etc");
}
