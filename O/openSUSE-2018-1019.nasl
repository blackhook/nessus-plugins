#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1019.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117526);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-1336", "CVE-2018-8014", "CVE-2018-8034", "CVE-2018-8037");

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-2018-1019)");
  script_summary(english:"Check for the openSUSE-2018-1019 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tomcat to 8.0.53 fixes the following issues :

Security issue fixed :

  - CVE-2018-1336: An improper handing of overflow in the
    UTF-8 decoder with supplementary characters could have
    lead to an infinite loop in the decoder causing a Denial
    of Service (bsc#1102400).

  - CVE-2018-8034: The host name verification when using TLS
    with the WebSocket client was missing. It is now enabled
    by default (bsc#1102379).

  - CVE-2018-8037: If an async request was completed by the
    application at the same time as the container triggered
    the async timeout, a race condition existed that could
    have resulted in a user seeing a response intended for a
    different user. An additional issue was present in the
    NIO and NIO2 connectors that did not correctly track the
    closure of the connection when an async request was
    completed by the application and timed out by the
    container at the same time. This could also have
    resulted in a user seeing a response intended for
    another user (bsc#1102410).

  - CVE-2018-8014: Fix insecure default CORS filter settings
    (bsc#1093697).

Bug fixes :

  - bsc#1067720: Avoid overwriting of customer's
    configuration during update.

  - bsc#1095472: Add Obsoletes for tomcat6 packages.

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1067720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1093697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1102410"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"tomcat-8.0.53-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-admin-webapps-8.0.53-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-docs-webapp-8.0.53-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-el-3_0-api-8.0.53-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-embed-8.0.53-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-javadoc-8.0.53-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-jsp-2_3-api-8.0.53-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-jsvc-8.0.53-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-lib-8.0.53-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-servlet-3_1-api-8.0.53-15.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"tomcat-webapps-8.0.53-15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
