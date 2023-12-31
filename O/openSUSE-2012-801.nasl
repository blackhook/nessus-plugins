#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-801.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74819);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-5533");

  script_name(english:"openSUSE Security Update : lighttpd (openSUSE-SU-2012:1532-1)");
  script_summary(english:"Check for the openSUSE-2012-801 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fixing bnc#790258 CVE-2012-5533: Denial of Service via
    specially crafted HTTP header. Added patches:
    0001-Fix-DoS-in-header-value-split-reported-by-Jesse-Sip
    p.patch
    0001-remove-whitespace-at-end-of-header-keys.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=790258"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2012-11/msg00044.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lighttpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_cml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_geoip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_geoip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_magnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_magnet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_mysql_vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_mysql_vhost-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_rrdtool-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_trigger_b4_dl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_trigger_b4_dl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_webdav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lighttpd-mod_webdav-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-debuginfo-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-debugsource-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_cml-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_cml-debuginfo-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_geoip-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_geoip-debuginfo-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_magnet-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_magnet-debuginfo-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_mysql_vhost-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_mysql_vhost-debuginfo-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_rrdtool-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_rrdtool-debuginfo-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_trigger_b4_dl-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_trigger_b4_dl-debuginfo-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_webdav-1.4.31-4.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"lighttpd-mod_webdav-debuginfo-1.4.31-4.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lighttpd / lighttpd-debuginfo / lighttpd-debugsource / etc");
}
