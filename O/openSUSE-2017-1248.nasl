#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1248.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104423);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-10911", "CVE-2017-12809", "CVE-2017-13672", "CVE-2017-13711", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15268", "CVE-2017-15289");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2017-1248)");
  script_summary(english:"Check for the openSUSE-2017-1248 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu to version 2.9.1 fixes several issues.

It also announces that the qed storage format will be no longer
supported in Leap 15.0.

These security issues were fixed :

  - CVE-2017-15268: Qemu allowed remote attackers to cause a
    memory leak by triggering slow data-channel read
    operations, related to io/channel-websock.c
    (bsc#1062942)

  - CVE-2017-15289: The mode4and5 write functions allowed
    local OS guest privileged users to cause a denial of
    service (out-of-bounds write access and Qemu process
    crash) via vectors related to dst calculation
    (bsc#1063122)

  - CVE-2017-15038: Race condition in the v9fs_xattrwalk
    function local guest OS users to obtain sensitive
    information from host heap memory via vectors related to
    reading extended attributes (bsc#1062069)

  - CVE-2017-10911: The make_response function in the Linux
    kernel allowed guest OS users to obtain sensitive
    information from host OS (or other guest OS) kernel
    memory by leveraging the copying of uninitialized
    padding fields in Xen block-interface response
    structures (bsc#1057378)

  - CVE-2017-12809: The IDE disk and CD/DVD-ROM Emulator
    support allowed local guest OS privileged users to cause
    a denial of service (NULL pointer dereference and QEMU
    process crash) by flushing an empty CDROM device drive
    (bsc#1054724)

  - CVE-2017-14167: Integer overflow in the load_multiboot
    function allowed local guest OS users to execute
    arbitrary code on the host via crafted multiboot header
    address values, which trigger an out-of-bounds write
    (bsc#1057585)

  - CVE-2017-13672: The VGA display emulator support allowed
    local guest OS privileged users to cause a denial of
    service (out-of-bounds read and QEMU process crash) via
    vectors involving display update (bsc#1056334)

  - CVE-2017-13711: Use-after-free vulnerability allowed
    attackers to cause a denial of service (QEMU instance
    crash) by leveraging failure to properly clear ifq_so
    from pending packets (bsc#1056291).

These non-security issues were fixed :

  - Fixed not being able to build from rpm sources due to
    undefined macro (bsc#1057966)

  - Fiedx package build failure against new glibc
    (bsc#1055587)

This update was imported from the SUSE:SLE-12-SP3:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1054724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1055587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063122"
  );
  # https://features.opensuse.org/324200
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE42.3", reference:"qemu-ipxe-1.0.0-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-linux-user-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-linux-user-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-linux-user-debugsource-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-seabios-1.10.2-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-sgabios-8-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"qemu-vgabios-1.10.2-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-arm-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-arm-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-curl-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-curl-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-dmg-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-dmg-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-iscsi-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-iscsi-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-rbd-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-ssh-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-block-ssh-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-debugsource-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-extra-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-extra-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-guest-agent-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-guest-agent-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-ksm-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-kvm-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-lang-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-ppc-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-ppc-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-s390-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-s390-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-testsuite-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-tools-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-tools-debuginfo-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-x86-2.9.1-35.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"qemu-x86-debuginfo-2.9.1-35.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-linux-user / qemu-linux-user-debuginfo / etc");
}
