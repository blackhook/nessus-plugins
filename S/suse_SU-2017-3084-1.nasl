#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:3084-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104780);
  script_version("3.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2016-10155", "CVE-2016-9602", "CVE-2016-9603", "CVE-2016-9776", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-10664", "CVE-2017-10806", "CVE-2017-11334", "CVE-2017-11434", "CVE-2017-13672", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15289", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5579", "CVE-2017-5856", "CVE-2017-5898", "CVE-2017-5973", "CVE-2017-6505", "CVE-2017-7471", "CVE-2017-7493", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8309", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9375", "CVE-2017-9503");
  script_xref(name:"IAVB", value:"2017-B-0024-S");

  script_name(english:"SUSE SLES11 Security Update : kvm (SUSE-SU-2017:3084-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kvm fixes several issues. These security issues were
fixed :

  - CVE-2017-2620: In CIRRUS_BLTMODE_MEMSYSSRC mode the
    bitblit copy routine cirrus_bitblt_cputovideo failed to
    check the memory region, allowing for an out-of-bounds
    write that allows for privilege escalation (bsc#1024972)

  - CVE-2017-2615: An error in the bitblt copy operation
    could have allowed a malicious guest administrator to
    cause an out of bounds memory access, possibly leading
    to information disclosure or privilege escalation
    (bsc#1023004)

  - CVE-2016-9776: The ColdFire Fast Ethernet Controller
    emulator support was vulnerable to an infinite loop
    issue while receiving packets in 'mcf_fec_receive'. A
    privileged user/process inside guest could have used
    this issue to crash the Qemu process on the host leading
    to DoS (bsc#1013285)

  - CVE-2016-9911: The USB EHCI Emulation support was
    vulnerable to a memory leakage issue while processing
    packet data in 'ehci_init_transfer'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for the host (bsc#1014111)

  - CVE-2016-9907: The USB redirector usb-guest support was
    vulnerable to a memory leakage flaw when destroying the
    USB redirector in 'usbredir_handle_destroy'. A guest
    user/process could have used this issue to leak host
    memory, resulting in DoS for a host (bsc#1014109)

  - CVE-2016-9921: The Cirrus CLGD 54xx VGA Emulator support
    was vulnerable to a divide by zero issue while copying
    VGA data. A privileged user inside guest could have used
    this flaw to crash the process instance on the host,
    resulting in DoS (bsc#1014702)

  - CVE-2016-9922: The Cirrus CLGD 54xx VGA Emulator support
    was vulnerable to a divide by zero issue while copying
    VGA data. A privileged user inside guest could have used
    this flaw to crash the process instance on the host,
    resulting in DoS (bsc#1014702)

  - CVE-2017-5898: The CCID Card device emulator support was
    vulnerable to an integer overflow allowing a privileged
    user inside the guest to crash the Qemu process
    resulting in DoS (bnc#1023907)

  - CVE-2016-10155: The virtual hardware watchdog
    'wdt_i6300esb' was vulnerable to a memory leakage issue
    allowing a privileged user to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1021129)

  - CVE-2017-5856: The MegaRAID SAS 8708EM2 Host Bus Adapter
    emulation support was vulnerable to a memory leakage
    issue allowing a privileged user to leak host memory
    resulting in DoS (bsc#1023053)

  - CVE-2016-9602: The VirtFS host directory sharing via
    Plan 9 File System(9pfs) support was vulnerable to an
    improper link following issue which allowed a privileged
    user inside guest to access host file system beyond the
    shared folder and potentially escalating their
    privileges on a host (bsc#1020427)

  - CVE-2016-9603: A privileged user within the guest VM
    could have caused a heap overflow in the device model
    process, potentially escalating their privileges to that
    of the device model process (bsc#1028656)

  - CVE-2017-10664: qemu-nbd did not ignore SIGPIPE, which
    allowed remote attackers to cause a denial of service
    (daemon crash) by disconnecting during a
    server-to-client reply attempt (bsc#1046636)

  - CVE-2017-10806: Stack-based buffer overflow allowed
    local guest OS users to cause a denial of service (QEMU
    process crash) via vectors related to logging debug
    messages (bsc#1047674)

  - CVE-2017-11334: The address_space_write_continue
    function allowed local guest OS privileged users to
    cause a denial of service (out-of-bounds access and
    guest instance crash) by leveraging use of
    qemu_map_ram_ptr to access guest ram block area
    (bsc#1048902)

  - CVE-2017-11434: The dhcp_decode function in
    slirp/bootp.c allowed local guest OS users to cause a
    denial of service (out-of-bounds read) via a crafted
    DHCP options string (bsc#1049381)

  - CVE-2017-13672: The VGA display emulator support allowed
    local guest OS privileged users to cause a denial of
    service (out-of-bounds read and QEMU process crash) via
    vectors involving display update (bsc#1056334)

  - CVE-2017-14167: Integer overflow in the load_multiboot
    function allowed local guest OS users to execute
    arbitrary code on the host via crafted multiboot header
    address values, which trigger an out-of-bounds write
    (bsc#1057585)

  - CVE-2017-15038: Race condition in the v9fs_xattrwalk
    function local guest OS users to obtain sensitive
    information from host heap memory via vectors related to
    reading extended attributes (bsc#1062069)

  - CVE-2017-15289: The mode4and5 write functions allowed
    local OS guest privileged users to cause a denial of
    service (out-of-bounds write access and Qemu process
    crash) via vectors related to dst calculation
    (bsc#1063122)

  - CVE-2017-5579: The 16550A UART serial device emulation
    support was vulnerable to a memory leakage issue
    allowing a privileged user to cause a DoS and/or
    potentially crash the Qemu process on the host
    (bsc#1021741)

  - CVE-2017-5973: A infinite loop while doing control
    transfer in xhci_kick_epctx allowed privileged user
    inside the guest to crash the host process resulting in
    DoS (bsc#1025109)

  - CVE-2017-6505: The ohci_service_ed_list function allowed
    local guest OS users to cause a denial of service
    (infinite loop) via vectors involving the number of link
    endpoint list descriptors (bsc#1028184)

  - CVE-2017-7471: The VirtFS host directory sharing via
    Plan 9 File System(9pfs) support was vulnerable to an
    improper access control issue which allowed a privileged
    user inside guest to access host file system beyond the
    shared folder and potentially escalating their
    privileges on a host (bsc#1034866)

  - CVE-2017-7493: The VirtFS, host directory sharing via
    Plan 9 File System(9pfs) support, was vulnerable to an
    improper access control issue. It could occur while
    accessing virtfs metadata files in mapped-file security
    mode. A guest user could have used this flaw to escalate
    their privileges inside guest (bsc#1039495)

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

  - CVE-2017-8086: A memory leak in the v9fs_list_xattr
    function in hw/9pfs/9p-xattr.c allowed local guest OS
    privileged users to cause a denial of service (memory
    consumption) via vectors involving the orig_value
    variable (bsc#1035950)

  - CVE-2017-8309: Memory leak in the audio/audio.c allowed
    remote attackers to cause a denial of service (memory
    consumption) by repeatedly starting and stopping audio
    capture (bsc#1037242)

  - CVE-2017-9330: USB OHCI Emulation in qemu allowed local
    guest OS users to cause a denial of service (infinite
    loop) by leveraging an incorrect return value
    (bsc#1042159)

  - CVE-2017-9373: The IDE AHCI Emulation support was
    vulnerable to a host memory leakage issue, which allowed
    a privileged user inside guest to leak host memory
    resulting in DoS (bsc#1042801)

  - CVE-2017-9375: The USB xHCI controller emulator support
    was vulnerable to an infinite recursive call loop issue,
    which allowed a privileged user inside guest to crash
    the Qemu process resulting in DoS (bsc#1042800)

  - CVE-2017-9503: The MegaRAID SAS 8708EM2 Host Bus Adapter
    emulation support was vulnerable to a NULL pointer
    dereference issue which allowed a privileged user inside
    guest to crash the Qemu process on the host resulting in
    DoS (bsc#1043296)

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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1013285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1014109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1014111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1014702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1015048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1016779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021129"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1021741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023004"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1023907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1024972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1025109"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1031051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1034044"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1037242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038396"
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
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1049785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1056334"
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
    value:"https://www.suse.com/security/cve/CVE-2016-10155/"
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
    value:"https://www.suse.com/security/cve/CVE-2016-9776/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9907/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9911/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9921/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9922/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-11334/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-11434/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-2615/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2620/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5579/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5856/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5898/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5973/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6505/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-8309/"
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
    value:"https://www.suse.com/security/cve/CVE-2017-9375/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-9503/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20173084-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f7a1339"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-kvm-13351=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-kvm-13351=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", reference:"kvm-1.4.2-53.11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvm");
}
