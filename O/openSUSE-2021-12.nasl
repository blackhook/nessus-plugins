#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-12.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145377);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-27218");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE Security Update : jetty-minimal (openSUSE-2021-12)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for jetty-minimal fixes the following issues :

  - jetty-minimal was upgraded to version 9.4.35.v20201120

  - CVE-2020-27218: Fixed an issue where buffer not
    correctly recycled in Gzip Request inflation
    (bsc#1179727).

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179727");
  script_set_attribute(attribute:"solution", value:
"Update the affected jetty-minimal packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-continuation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-jaas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-javax-websocket-client-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-javax-websocket-server-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-jndi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-jsp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-minimal-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-openid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-plus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-security");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-servlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-util-ajax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-websocket-servlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jetty-xml");
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

if ( rpm_check(release:"SUSE15.2", reference:"jetty-annotations-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-client-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-continuation-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-http-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-io-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-jaas-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-javax-websocket-client-impl-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-javax-websocket-server-impl-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-jmx-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-jndi-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-jsp-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-minimal-javadoc-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-openid-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-plus-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-proxy-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-security-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-server-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-servlet-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-util-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-util-ajax-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-webapp-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-websocket-api-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-websocket-client-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-websocket-common-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-websocket-javadoc-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-websocket-server-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-websocket-servlet-9.4.35-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"jetty-xml-9.4.35-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jetty-annotations / jetty-client / jetty-continuation / jetty-http / etc");
}
