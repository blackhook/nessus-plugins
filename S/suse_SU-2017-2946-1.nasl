#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2946-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104471);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2016-6834", "CVE-2016-6835", "CVE-2016-9602", "CVE-2016-9603", "CVE-2017-10664", "CVE-2017-10806", "CVE-2017-10911", "CVE-2017-11334", "CVE-2017-11434", "CVE-2017-12809", "CVE-2017-13672", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15289", "CVE-2017-5579", "CVE-2017-5973", "CVE-2017-5987", "CVE-2017-6505", "CVE-2017-7377", "CVE-2017-7471", "CVE-2017-7493", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8112", "CVE-2017-8309", "CVE-2017-8379", "CVE-2017-8380", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9375", "CVE-2017-9503");

  script_name(english:"SUSE SLES12 Security Update : qemu (SUSE-SU-2017:2946-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu fixes several issues. These security issues were
fixed :

  - CVE-2017-10911: The make_response function in the Linux
    kernel allowed guest OS users to obtain sensitive
    information from host OS (or other guest OS) kernel
    memory by leveraging the copying of uninitialized
    padding fields in Xen block-interface response
    structures (bsc#1057378).

  - CVE-2017-12809: The IDE disk and CD/DVD-ROM Emulator
    support allowed local guest OS privileged users to cause
    a denial of service (NULL pointer dereference and QEMU
    process crash) by flushing an empty CDROM device drive
    (bsc#1054724).

  - CVE-2017-15289: The mode4and5 write functions allowed
    local OS guest privileged users to cause a denial of
    service (out-of-bounds write access and Qemu process
    crash) via vectors related to dst calculation
    (bsc#1063122)

  - CVE-2017-15038: Race condition in the v9fs_xattrwalk
    function local guest OS users to obtain sensitive
    information from host heap memory via vectors related to
    reading extended attributes (bsc#1062069)

  - CVE-2017-14167: Integer overflow in the load_multiboot
    function allowed local guest OS users to execute
    arbitrary code on the host via crafted multiboot header
    address values, which trigger an out-of-bounds write
    (bsc#1057585)

  - CVE-2017-11434: The dhcp_decode function in
    slirp/bootp.c allowed local guest OS users to cause a
    denial of service (out-of-bounds read) via a crafted
    DHCP options string (bsc#1049381)

  - CVE-2017-11334: The address_space_write_continue
    function allowed local guest OS privileged users to
    cause a denial of service (out-of-bounds access and
    guest instance crash) by leveraging use of
    qemu_map_ram_ptr to access guest ram block area
    (bsc#1048902)

  - CVE-2017-13672: The VGA display emulator support allowed
    local guest OS privileged users to cause a denial of
    service (out-of-bounds read and QEMU process crash) via
    vectors involving display update (bsc#1056334)

  - CVE-2017-5973: A infinite loop while doing control
    transfer in xhci_kick_epctx allowed privileged user
    inside the guest to crash the host process resulting in
    DoS (bsc#1025109)

  - CVE-2017-5987: The sdhci_sdma_transfer_multi_blocks
    function in hw/sd/sdhci.c allowed local OS guest
    privileged users to cause a denial of service (infinite
    loop and QEMU process crash) via vectors involving the
    transfer mode register during multi block transfer
    (bsc#1025311)

  - CVE-2017-6505: The ohci_service_ed_list function allowed
    local guest OS users to cause a denial of service
    (infinite loop) via vectors involving the number of link
    endpoint list descriptors (bsc#1028184)

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
    page count (bsc#1036211)

  - CVE-2017-9375: The USB xHCI controller emulator support
    was vulnerable to an infinite recursive call loop issue,
    which allowed a privileged user inside guest to crash
    the Qemu process resulting in DoS (bsc#1042800)

  - CVE-2017-9374: Missing free of 's->ipacket', causes a
    host memory leak, allowing for DoS (bsc#1043073)

  - CVE-2017-9373: The IDE AHCI Emulation support was
    vulnerable to a host memory leakage issue, which allowed
    a privileged user inside guest to leak host memory
    resulting in DoS (bsc#1042801)

  - CVE-2017-9330: USB OHCI Emulation in qemu allowed local
    guest OS users to cause a denial of service (infinite
    loop) by leveraging an incorrect return value
    (bsc#1042159)

  - CVE-2017-8379: Memory leak in the keyboard input event
    handlers support allowed local guest OS privileged users
    to cause a denial of service (host memory consumption)
    by rapidly generating large keyboard events
    (bsc#1037334)

  - CVE-2017-8309: Memory leak in the audio/audio.c allowed
    remote attackers to cause a denial of service (memory
    consumption) by repeatedly starting and stopping audio
    capture (bsc#1037242)

  - CVE-2017-8380: The MegaRAID SAS 8708EM2 Host Bus Adapter
    emulation support was vulnerable to an out-of-bounds
    read access issue which allowed a privileged user inside
    guest to read host memory resulting in DoS (bsc#1037336)

  - CVE-2017-7493: The VirtFS, host directory sharing via
    Plan 9 File System(9pfs) support, was vulnerable to an
    improper access control issue. It could occur while
    accessing virtfs metadata files in mapped-file security
    mode. A guest user could have used this flaw to escalate
    their privileges inside guest (bsc#1039495)

  - CVE-2016-9602: The VirtFS host directory sharing via
    Plan 9 File System(9pfs) support was vulnerable to an
    improper link following issue which allowed a privileged
    user inside guest to access host file system beyond the
    shared folder and potentially escalating their
    privileges on a host (bsc#1020427)

  - CVE-2017-5579: The 16550A UART serial device emulation
    support was vulnerable to a memory leakage issue
    allowing a privileged user to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1021741)

  - CVE-2017-9503: The MegaRAID SAS 8708EM2 Host Bus Adapter
    emulation support was vulnerable to a NULL pointer
    dereference issue which allowed a privileged user inside
    guest to crash the Qemu process on the host resulting in
    DoS (bsc#1043296)

  - CVE-2017-10664: qemu-nbd did not ignore SIGPIPE, which
    allowed remote attackers to cause a denial of service
    (daemon crash) by disconnecting during a
    server-to-client reply attempt (bsc#1046636)

  - CVE-2017-10806: Stack-based buffer overflow allowed
    local guest OS users to cause a denial of service (QEMU
    process crash) via vectors related to logging debug
    messages (bsc#1047674)

  - CVE-2016-9602: The VirtFS host directory sharing via
    Plan 9 File System(9pfs) support was vulnerable to an
    improper link following issue which allowed a privileged
    user inside guest to access host file system beyond the
    shared folder and potentially escalating their
    privileges on a host (bsc#1020427)

  - CVE-2017-7377: The v9fs_create and v9fs_lcreate
    functions in hw/9pfs/9p.c allowed local guest OS
    privileged users to cause a denial of service (file
    descriptor or memory consumption) via vectors related to
    an already in-use fid (bsc#1032075)

  - CVE-2017-8086: A memory leak in the v9fs_list_xattr
    function in hw/9pfs/9p-xattr.c allowed local guest OS
    privileged users to cause a denial of service (memory
    consumption) via vectors involving the orig_value
    variable (bsc#1035950)

  - CVE-2017-7471: The VirtFS host directory sharing via
    Plan 9 File System(9pfs) support was vulnerable to an
    improper access control issue which allowed a privileged
    user inside guest to access host file system beyond the
    shared folder and potentially escalating their
    privileges on a host (bsc#1034866)

  - CVE-2016-6835: Buffer overflow in the VMWARE VMXNET3 NIC
    device support, causing an OOB read access (bsc#994605)

  - CVE-2016-6834: A infinite loop during packet
    fragmentation in the VMWARE VMXNET3 NIC device support
    allowed privileged user inside guest to crash the Qemu
    instance resulting in DoS (bsc#994418)

  - Fix privilege escalation in TCG mode (bsc#1030624)

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1025109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1025311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1028184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1028656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1032075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1042159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1042800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1042801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1045035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1046636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1047674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1048902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1054724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1057585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1062069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=994605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6834/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6835/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9602/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9603/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10664/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10806/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-10911/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11334/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11434/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-12809/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-13672/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-14167/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15038/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-15289/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5579/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5973/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5987/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6505/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7377/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7471/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7493/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7718/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7980/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8086/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8112/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8309/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8379/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8380/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9330/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9373/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9374/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9375/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9503/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172946-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4becc028"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2017-1827=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2017-1827=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-1827=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-block-rbd-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-block-rbd-debuginfo-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"qemu-x86-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"qemu-s390-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"qemu-s390-debuginfo-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-block-curl-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-block-curl-debuginfo-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-debugsource-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-guest-agent-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-guest-agent-debuginfo-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-lang-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-tools-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-tools-debuginfo-2.3.1-33.3.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"qemu-kvm-2.3.1-33.3.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
