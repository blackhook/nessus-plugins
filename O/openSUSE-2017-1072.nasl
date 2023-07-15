#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1072.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103292);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10664", "CVE-2017-10806", "CVE-2017-11334", "CVE-2017-11434");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2017-1072)");
  script_summary(english:"Check for the openSUSE-2017-1072 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu fixes the following issues :

Security issues fixed :

  - CVE-2017-10664: Fix DOS vulnerability in qemu-nbd
    (bsc#1046636)

  - CVE-2017-10806: Fix DOS from stack overflow in debug
    messages of usb redirection support (bsc#1047674) 

  - CVE-2017-11334: Fix OOB access during DMA operation
    (bsc#1048902) 

  - CVE-2017-11434: Fix OOB access parsing dhcp slirp
    options (bsc#1049381) 

Following non-security issues were fixed :

  - Postrequire acl for setfacl

  - Prerequire shadow for groupadd

  - The recent security fix for CVE-2017-11334 adversely
    affects Xen. Include two additional patches to make sure
    Xen is going to be OK.

  - Pre-add group kvm for qemu-tools (bsc#1011144)

  - Fixed a few more inaccuracies in the support docs.

  - Fix support docs to indicate ARM64 is now fully L3
    supported in SLES 12 SP3. Apply a few additional
    clarifications in the support docs. (bsc#1050268)

  - Adjust to libvdeplug-devel package naming changes.

  - Fix migration with xhci (bsc#1048296)

  - Increase VNC delay to fix missing keyboard input events
    (bsc#1031692)

  - Remove build dependency package iasl used for seabios

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1046636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1049381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050268"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ksm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/18");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"qemu-ipxe-1.0.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-linux-user-2.9.0-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-linux-user-debuginfo-2.9.0-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-linux-user-debugsource-2.9.0-32.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-seabios-1.10.2-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-sgabios-8-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-vgabios-1.10.2-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-arm-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-arm-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-curl-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-dmg-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-dmg-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-iscsi-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-iscsi-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-rbd-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-ssh-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-ssh-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-debugsource-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-extra-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-extra-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-guest-agent-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-guest-agent-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-ksm-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-kvm-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-lang-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-ppc-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-ppc-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-s390-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-s390-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-testsuite-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-tools-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-x86-2.9.0-32.4") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-x86-debuginfo-2.9.0-32.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-linux-user / qemu-linux-user-debuginfo / etc");
}
