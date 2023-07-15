#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1177.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104081);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12176", "CVE-2017-12177", "CVE-2017-12178", "CVE-2017-12179", "CVE-2017-12180", "CVE-2017-12181", "CVE-2017-12182", "CVE-2017-12183", "CVE-2017-12184", "CVE-2017-12185", "CVE-2017-12186", "CVE-2017-12187");

  script_name(english:"openSUSE Security Update : xorg-x11-server (openSUSE-2017-1177)");
  script_summary(english:"Check for the openSUSE-2017-1177 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xorg-x11-server fixes the following vulnerabilities :

  - CVE-2017-12176: Unvalidated extra length in
    ProcEstablishConnection (bsc#1063041)

  - CVE-2017-12177: dbe: Unvalidated variable-length request
    in ProcDbeGetVisualInfo (bsc#1063040)

  - CVE-2017-12178: Xi: fix wrong extra length check in
    ProcXIChangeHierarchy (bsc#1063039)

  - CVE-2017-12179: Xi: integer overflow and unvalidated
    length in (S)ProcXIBarrierReleasePointer (bsc#1063038)

  - CVE-2017-12180,CVE-2017-12181,CVE-2017-12182:
    Unvalidated lengths in
    XFree86-VidMode/XFree86-DGA/XFree86-DRI extension
    (bsc#1063037)

  - CVE-2017-12183: Unvalidated lengths in XFIXES extension
    (bsc#1063035)

  -
    CVE-2017-12184,CVE-2017-12185,CVE-2017-12186,CVE-2017-12
    187: Unvalidated lengths in multiple extensions
    (bsc#1063034)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063037"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063041"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-7.6_1.18.3-12.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-debuginfo-7.6_1.18.3-12.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-debugsource-7.6_1.18.3-12.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-extra-7.6_1.18.3-12.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-extra-debuginfo-7.6_1.18.3-12.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-sdk-7.6_1.18.3-12.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"xorg-x11-server-source-7.6_1.18.3-12.26.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xorg-x11-server-7.6_1.18.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xorg-x11-server-debuginfo-7.6_1.18.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xorg-x11-server-debugsource-7.6_1.18.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xorg-x11-server-extra-7.6_1.18.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xorg-x11-server-extra-debuginfo-7.6_1.18.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xorg-x11-server-sdk-7.6_1.18.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"xorg-x11-server-source-7.6_1.18.3-28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server / xorg-x11-server-debuginfo / etc");
}
