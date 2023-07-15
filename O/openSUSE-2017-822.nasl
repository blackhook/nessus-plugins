#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-822.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101758);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-10028", "CVE-2016-10029", "CVE-2016-9602", "CVE-2016-9603", "CVE-2017-5579", "CVE-2017-5973", "CVE-2017-5987", "CVE-2017-6505", "CVE-2017-7377", "CVE-2017-7471", "CVE-2017-7493", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8112", "CVE-2017-8309", "CVE-2017-8379", "CVE-2017-8380", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9375", "CVE-2017-9503");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2017-822)");
  script_summary(english:"Check for the openSUSE-2017-822 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu fixes several issues.

These security issues were fixed :

  - CVE-2017-9330: USB OHCI Emulation in qemu allowed local
    guest OS users to cause a denial of service (infinite
    loop) by leveraging an incorrect return value
    (bsc#1042159).

  - CVE-2017-8379: Memory leak in the keyboard input event
    handlers support allowed local guest OS privileged users
    to cause a denial of service (host memory consumption)
    by rapidly generating large keyboard events
    (bsc#1037334).

  - CVE-2017-8309: Memory leak in the audio/audio.c allowed
    remote attackers to cause a denial of service (memory
    consumption) by repeatedly starting and stopping audio
    capture (bsc#1037242).

  - CVE-2017-7493: The VirtFS, host directory sharing via
    Plan 9 File System(9pfs) support, was vulnerable to an
    improper access control issue. It could occur while
    accessing virtfs metadata files in mapped-file security
    mode. A guest user could have used this flaw to escalate
    their privileges inside guest (bsc#1039495).

  - CVE-2017-7377: The v9fs_create and v9fs_lcreate
    functions in hw/9pfs/9p.c allowed local guest OS
    privileged users to cause a denial of service (file
    descriptor or memory consumption) via vectors related to
    an already in-use fid (bsc#1032075).

  - CVE-2017-8086: A memory leak in the v9fs_list_xattr
    function in hw/9pfs/9p-xattr.c allowed local guest OS
    privileged users to cause a denial of service (memory
    consumption) via vectors involving the orig_value
    variable (bsc#1035950).

  - CVE-2017-5973: A infinite loop while doing control
    transfer in xhci_kick_epctx allowed privileged user
    inside the guest to crash the host process resulting in
    DoS (bsc#1025109)

  - CVE-2017-5987: The sdhci_sdma_transfer_multi_blocks
    function in hw/sd/sdhci.c allowed local OS guest
    privileged users to cause a denial of service (infinite
    loop and QEMU process crash) via vectors involving the
    transfer mode register during multi block transfer
    (bsc#1025311).

  - CVE-2017-6505: The ohci_service_ed_list function in
    hw/usb/hcd-ohci.c allowed local guest OS users to cause
    a denial of service (infinite loop) via vectors
    involving the number of link endpoint list descriptors
    (bsc#1028184)

  - CVE-2016-9603: A privileged user within the guest VM
    could have caused a heap overflow in the device model
    process, potentially escalating their privileges to that
    of the device model process (bsc#1028656)

  - CVE-2017-7718: hw/display/cirrus_vga_rop.h allowed local
    guest OS privileged users to cause a denial of service
    (out-of-bounds read and QEMU process crash) via vectors
    related to copying VGA data via the
    cirrus_bitblt_rop_fwd_transp_ and cirrus_bitblt_rop_fwd_
    functions (bsc#1034908)

  - CVE-2017-7980: An out-of-bounds r/w access issues in the
    Cirrus CLGD 54xx VGA Emulator support allowed privileged
    user inside guest to use this flaw to crash the Qemu
    process resulting in DoS or potentially execute
    arbitrary code on a host with privileges of Qemu process
    on the host (bsc#1035406)

  - CVE-2017-8112: hw/scsi/vmw_pvscsi.c allowed local guest
    OS privileged users to cause a denial of service
    (infinite loop and CPU consumption) via the message ring
    page count (bsc#1036211).

  - CVE-2017-9375: The USB xHCI controller emulator support
    was vulnerable to an infinite recursive call loop issue,
    which allowed a privileged user inside guest to crash
    the Qemu process resulting in DoS (bsc#1042800).

  - CVE-2017-9374: Missing free of 's->ipacket', causes a
    host memory leak, allowing for DoS (bsc#1043073).

  - CVE-2017-9373: The IDE AHCI Emulation support was
    vulnerable to a host memory leakage issue, which allowed
    a privileged user inside guest to leak host memory
    resulting in DoS (bsc#1042801).

  - CVE-2017-8380: The MegaRAID SAS 8708EM2 Host Bus Adapter
    emulation support was vulnerable to an out-of-bounds
    read access issue which allowed a privileged user inside
    guest to read host memory resulting in DoS
    (bsc#1037336).

  - CVE-2016-9602: The VirtFS host directory sharing via
    Plan 9 File System(9pfs) support was vulnerable to an
    improper link following issue which allowed a privileged
    user inside guest to access host file system beyond the
    shared folder and potentially escalating their
    privileges on a host (bsc#1020427).

  - CVE-2017-7471: The VirtFS host directory sharing via
    Plan 9 File System(9pfs) support was vulnerable to an
    improper access control issue which allowed a privileged
    user inside guest to access host file system beyond the
    shared folder and potentially escalating their
    privileges on a host (bsc#1034866).

  - Fix privilege escalation in TCG mode of QEMU. This is
    not considered a security issue by the upstream project,
    but is included as additional hardening (bsc#1030624)

  - Fix potential DoS in virtfs

  - CVE-2016-10028: The Virtio GPU Device emulator support
    was vulnerable to an out of bounds memory access issue
    allowing a guest user to crash the Qemu process instance
    on a host, resulting in DoS (bsc#1017084, bsc#1016503)

  - CVE-2016-10029: The Virtio GPU Device emulator support
    was vulnerable to an OOB read issue allowing a guest
    user to crash the Qemu process instance resulting in Dos
    (bsc#1017081, bsc#1016504)

  - CVE-2017-5579: The 16550A UART serial device emulation
    support was vulnerable to a memory leakage issue
    allowing a privileged user to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1021741)

  - CVE-2017-9503: The MegaRAID SAS 8708EM2 Host Bus Adapter
    emulation support was vulnerable to a NULL pointer
    dereference issue which allowed a privileged user inside
    guest to crash the Qemu process on the host resulting in
    DoS (bsc#1043296).

This non-security issue was fixed :

  - Enable MONITOR/MWAIT support for guests (bsc#1031142)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1016504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1021741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1031142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1032075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1034908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1037336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1043296"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/17");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"qemu-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-arm-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-arm-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-curl-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-curl-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-dmg-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-dmg-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-iscsi-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-iscsi-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-ssh-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-block-ssh-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-debugsource-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-extra-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-extra-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-guest-agent-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-guest-agent-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-ipxe-1.0.0-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-kvm-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-lang-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-linux-user-2.6.2-31.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-linux-user-debuginfo-2.6.2-31.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-linux-user-debugsource-2.6.2-31.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-ppc-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-ppc-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-s390-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-s390-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-seabios-1.9.1-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-sgabios-8-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-testsuite-2.6.2-31.3.6") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-tools-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-tools-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-vgabios-1.9.1-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-x86-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qemu-x86-debuginfo-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"qemu-block-rbd-2.6.2-31.3.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.6.2-31.3.3") ) flag++;

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
