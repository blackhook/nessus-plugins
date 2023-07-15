#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-76.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(145292);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2020-13428", "CVE-2020-26664");

  script_name(english:"openSUSE Security Update : vlc (openSUSE-2021-76)");
  script_summary(english:"Check for the openSUSE-2021-76 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for vlc fixes the following issues :

Update to 3.0.11.1 :

  - CVE-2020-13428: Fixed heap-based buffer overflow in the
    hxxx_AnnexB_to_xVC () (boo#1172727)

  - CVE-2020-26664: Fixed heap-based buffer overflow in
    EbmlTypeDispatcher:send () (boo#1180755)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1172727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180755"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vlc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlc5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvlccore9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-codec-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-codec-gstreamer-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-jack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-jack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-noX-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-vdpau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vlc-vdpau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libvlc5-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvlc5-debuginfo-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvlccore9-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libvlccore9-debuginfo-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-codec-gstreamer-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-codec-gstreamer-debuginfo-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-debuginfo-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-debugsource-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-devel-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-jack-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-jack-debuginfo-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-lang-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-noX-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-noX-debuginfo-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-opencv-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-opencv-debuginfo-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-qt-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-qt-debuginfo-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-vdpau-3.0.11.1-lp151.6.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"vlc-vdpau-debuginfo-3.0.11.1-lp151.6.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvlc5 / libvlc5-debuginfo / libvlccore9 / libvlccore9-debuginfo / etc");
}
