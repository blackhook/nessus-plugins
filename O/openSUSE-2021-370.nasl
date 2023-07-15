#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-370.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(147159);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id("CVE-2021-26720");

  script_name(english:"openSUSE Security Update : avahi (openSUSE-2021-370)");
  script_summary(english:"Check for the openSUSE-2021-370 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for avahi fixes the following issues :

  - CVE-2021-26720: drop privileges when invoking
    avahi-daemon-check-dns.sh (bsc#1180827)

  - Update avahi-daemon-check-dns.sh from Debian. Our
    previous version relied on ifconfig, route, and init.d.

  - Add sudo to requires: used to drop privileges.

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180827"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected avahi packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-autoipd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-compat-mDNSResponder-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-glib2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-qt4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-utils-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:avahi-utils-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-client3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-client3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-client3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-common3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-common3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-common3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-core7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-core7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-glib1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-glib1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-glib1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-gobject0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-qt4-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-qt4-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-ui-gtk3-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-ui-gtk3-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-ui0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libavahi-ui0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns_sd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns_sd-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdns_sd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhowl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libhowl0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-avahi-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-Avahi-0_6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"avahi-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-autoipd-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-autoipd-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-compat-howl-devel-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-compat-mDNSResponder-devel-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-debugsource-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-glib2-debugsource-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-lang-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-utils-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-utils-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-utils-gtk-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"avahi-utils-gtk-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-client3-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-client3-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-common3-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-common3-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-core7-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-core7-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-devel-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-glib-devel-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-glib1-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-glib1-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-gobject-devel-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-gobject0-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-gobject0-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-ui-gtk3-0-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-ui-gtk3-0-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-ui0-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libavahi-ui0-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdns_sd-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libdns_sd-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libhowl0-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libhowl0-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-avahi-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-avahi-gtk-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"typelib-1_0-Avahi-0_6-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"avahi-32bit-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"avahi-mono-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"avahi-qt4-debugsource-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libavahi-client3-32bit-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libavahi-client3-32bit-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libavahi-common3-32bit-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libavahi-common3-32bit-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libavahi-glib1-32bit-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libavahi-glib1-32bit-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libavahi-qt4-1-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libavahi-qt4-1-debuginfo-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libavahi-qt4-devel-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libdns_sd-32bit-0.7-lp152.3.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libdns_sd-32bit-debuginfo-0.7-lp152.3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi-glib2-debugsource / avahi-utils-gtk / etc");
}
