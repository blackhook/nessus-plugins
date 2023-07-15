#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1267.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104525);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10392", "CVE-2017-10407", "CVE-2017-10408", "CVE-2017-10428");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2017-1267)");
  script_summary(english:"Check for the openSUSE-2017-1267 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virtualbox fixes the following issues :

  - CVE-2017-10392: A local user can exploit a flaw in the
    Oracle VM VirtualBox Core component to partially access
    data, partially modify data, and deny service

  - CVE-2017-10407: A local user can exploit a flaw in the
    Oracle VM VirtualBox Core component to partially access
    data, partially modify data, and deny service

  - CVE-2017-10408: A local user can exploit a flaw in the
    Oracle VM VirtualBox Core component to partially access
    data, partially modify data, and deny service

  - CVE-2017-10428: A local user can exploit a flaw in the
    Oracle VM VirtualBox Core component to partially access
    data, partially modify data, and partially deny service

The following packaging changes are included :

  - Further to usage of vboxdrv if virtualbox-qt is not
    installed: updates to vboxdrv.sh (boo#1060072)

  - The virtualbox package no longer requires libX11, an
    library module files were moved to virtualbox-qt

This update also contains all upstream improvements in the 5.1.30
release, including :

  - Fix for double mouse cursor when using mouse integration
    without Guest Additions.

  - Translation updates"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1066488"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/13");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"python-virtualbox-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"python-virtualbox-debuginfo-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-debuginfo-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-debugsource-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-devel-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-desktop-icons-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-kmp-default-5.1.30_k4.4.92_18.36-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-kmp-default-debuginfo-5.1.30_k4.4.92_18.36-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-source-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-tools-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-tools-debuginfo-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-x11-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-guest-x11-debuginfo-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-kmp-default-5.1.30_k4.4.92_18.36-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-kmp-default-debuginfo-5.1.30_k4.4.92_18.36-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-host-source-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-qt-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-qt-debuginfo-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-vnc-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-websrv-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"virtualbox-websrv-debuginfo-5.1.30-19.46.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-virtualbox-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-virtualbox-debuginfo-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-debuginfo-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-debugsource-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-devel-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-desktop-icons-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-kmp-default-5.1.30_k4.4.92_31-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-kmp-default-debuginfo-5.1.30_k4.4.92_31-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-source-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-tools-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-tools-debuginfo-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-x11-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-guest-x11-debuginfo-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-kmp-default-5.1.30_k4.4.92_31-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-kmp-default-debuginfo-5.1.30_k4.4.92_31-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-host-source-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-qt-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-qt-debuginfo-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-vnc-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-websrv-5.1.30-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"virtualbox-websrv-debuginfo-5.1.30-39.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-virtualbox / python-virtualbox-debuginfo / virtualbox / etc");
}
