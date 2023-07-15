#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1486.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140692);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2020-14628", "CVE-2020-14629", "CVE-2020-14646", "CVE-2020-14647", "CVE-2020-14648", "CVE-2020-14649", "CVE-2020-14650", "CVE-2020-14673", "CVE-2020-14674", "CVE-2020-14675", "CVE-2020-14676", "CVE-2020-14677", "CVE-2020-14694", "CVE-2020-14695", "CVE-2020-14698", "CVE-2020-14699", "CVE-2020-14700", "CVE-2020-14703", "CVE-2020-14704", "CVE-2020-14707", "CVE-2020-14711", "CVE-2020-14712", "CVE-2020-14713", "CVE-2020-14714", "CVE-2020-14715");

  script_name(english:"openSUSE Security Update : virtualbox (openSUSE-2020-1486)");
  script_summary(english:"Check for the openSUSE-2020-1486 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for virtualbox fixes the following issues :

Update to Oracle version 6.1.14a.

This minor update enables the building of libvirt again.

Version update to 6.1.14 (released September 04 2020 by Oracle)

File 'fix_virtio_build.patch' is added to fix a build problem. This is
a maintenance release. The following items were fixed and/or added:
GUI: Fixes file name changes in the File location field when creating
Virtual Hard Disk (bug #19286) VMM: Fixed running VMs which failed to
start with VERR_NEM_MISSING_KERNEL_API_2 when Hyper-V is used (bug
#19779 and #19804) Audio: fix regression in HDA emulation introduced
in 6.1.0 Shared Clipboard: Fixed a potential crash when copying HTML
data (6.1.2 regression; bug #19226) Linux host and guest: Linux kernel
version 5.8 support EFI: Fixed reading ISO9660 filesystems on attached
media (6.1.0 regression; bug #19682) EFI: Support booting from drives
attached to the LsiLogic SCSI and SAS controller emulations

Pseudo version bump to 6.1.13, which is NOT an Oracle release.

Update VB sources to run under kernel 5.8.0+ with no modifications to
the kernel. These sources are derived from r85883 of the Oracle svn
repository. For operations with USB(2,3), the extension pack for
revision 140056 must be installed. Once Oracle releases 6.1.14, then
the extension pack and VB itself will have the same revision number.
File 'fixes_for_5.8.patch' is removed as that part was fixed upstream.
Fixes boo#1175201.

Apply Oracle changes for kernel 5.8.

Version bump to 6.1.12 (released July 14 2020 by Oracle)

This is a maintenance release. The following items were fixed and/or
added: File 'turn_off_cloud_net.patch' added. Fixes for
CVE-2020-14628, CVE-2020-14646, CVE-2020-14647, CVE-2020-14649 &#9;
&#9; CVE-2020-14713, CVE-2020-14674, CVE-2020-14675, CVE-2020-14676
&#9; &#9; CVE-2020-14677, CVE-2020-14699, CVE-2020-14711,
CVE-2020-14629 &#9; CVE-2020-14703, CVE-2020-14704, CVE-2020-14648,
CVE-2020-14650 &#9; CVE-2020-14673, CVE-2020-14694, CVE-2020-14695,
CVE-2020-14698 &#9;&#9; CVE-2020-14700, CVE-2020-14712,
CVE-2020-14707, CVE-2020-14714&#9; CVE-2020-14715 boo#1174159. UI:
Fixes for Log-Viewer search-backward icon Devices: Fixes and
improvements for the BusLogic SCSI controller emulation Serial Port:
Regression fixes in FIFO data handling Oracle Cloud Infrastructure
integration: Experimental new type of network attachment, allowing
local VM to act as if it was run in cloud API: improved resource
management in the guest control functionality VBoxManage: fixed
command option parsing for the 'snapshot edit' sub-command VBoxManage:
Fix crash of 'VBoxManage internalcommands repairhd' when processing
invalid input (bug #19579) Guest Additions, 3D: New experimental GLX
graphics output Guest Additions, 3D: Fixed releasing texture objects,
which could cause guest crashes Guest Additions: Fixed writes to a
file on a shared folder not being reflected on the host when the file
is mmap'ed and the used Linux kernel is between version 4.10.0 and
4.11.x Guest Additions: Fixed the shared folder driver on 32bit
Windows 8 and newer returning an error when flushing writes to a file
which is mapped into memory under rare circumstances Guest Additions:
Improve resize coverage for VMSVGA graphics controller Guest
Additions: Fix issues detecting guest additions ISO at runtime Guest
Additions: Fixed German translation encoding for Windows GA installer"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175201"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected virtualbox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14704");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-kmp-preempt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"python3-virtualbox-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-virtualbox-debuginfo-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-debuginfo-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-debugsource-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-devel-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-desktop-icons-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-source-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-tools-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-tools-debuginfo-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-x11-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-guest-x11-debuginfo-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-host-source-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-debugsource-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-default-6.1.14_k5.3.18_lp152.41-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-default-debuginfo-6.1.14_k5.3.18_lp152.41-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-preempt-6.1.14_k5.3.18_lp152.41-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-kmp-preempt-debuginfo-6.1.14_k5.3.18_lp152.41-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-qt-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-qt-debuginfo-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-vnc-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-websrv-6.1.14-lp152.2.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"virtualbox-websrv-debuginfo-6.1.14-lp152.2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-virtualbox / python3-virtualbox-debuginfo / virtualbox / etc");
}
