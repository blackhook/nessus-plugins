#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1154-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90759);
  script_version("2.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2014-0222", "CVE-2014-3640", "CVE-2014-3689", "CVE-2014-7815", "CVE-2015-5278", "CVE-2015-7512", "CVE-2015-8504", "CVE-2015-8550", "CVE-2015-8554", "CVE-2015-8555", "CVE-2015-8558", "CVE-2015-8743", "CVE-2015-8745", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-1714", "CVE-2016-1981", "CVE-2016-2270", "CVE-2016-2271", "CVE-2016-2391", "CVE-2016-2841");
  script_bugtraq_id(67357, 67483, 70237, 70997, 70998);

  script_name(english:"SUSE SLES11 Security Update : xen (SUSE-SU-2016:1154-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"xen was updated to fix 27 security issues.

These security issues were fixed :

  - CVE-2013-4533: Buffer overflow in the pxa2xx_ssp_load
    function in hw/arm/pxa2xx.c allowed remote attackers to
    cause a denial of service or possibly execute arbitrary
    code via a crafted s->rx_level value in a savevm image
    (bsc#864655).

  - CVE-2013-4534: Buffer overflow in hw/intc/openpic.c
    allowed remote attackers to cause a denial of service or
    possibly execute arbitrary code via vectors related to
    IRQDest elements (bsc#864811).

  - CVE-2013-4537: The ssi_sd_transfer function in
    hw/sd/ssi-sd.c allowed remote attackers to execute
    arbitrary code via a crafted arglen value in a savevm
    image (bsc#864391).

  - CVE-2013-4538: Multiple buffer overflows in the
    ssd0323_load function in hw/display/ssd0323.c allowed
    remote attackers to cause a denial of service (memory
    corruption) or possibly execute arbitrary code via
    crafted (1) cmd_len, (2) row, or (3) col values; (4)
    row_start and row_end values; or (5) col_star and
    col_end values in a savevm image (bsc#864769).

  - CVE-2013-4539: Multiple buffer overflows in the
    tsc210x_load function in hw/input/tsc210x.c might have
    allowed remote attackers to execute arbitrary code via a
    crafted (1) precision, (2) nextprecision, (3) function,
    or (4) nextfunction value in a savevm image
    (bsc#864805).

  - CVE-2014-0222: Integer overflow in the qcow_open
    function in block/qcow.c allowed remote attackers to
    cause a denial of service (crash) via a large L2 table
    in a QCOW version 1 image (bsc#877642).

  - CVE-2014-3640: The sosendto function in slirp/udp.c
    allowed local users to cause a denial of service (NULL
    pointer dereference) by sending a udp packet with a
    value of 0 in the source port and address, which
    triggers access of an uninitialized socket (bsc#897654).

  - CVE-2014-3689: The vmware-vga driver
    (hw/display/vmware_vga.c) allowed local guest users to
    write to qemu memory locations and gain privileges via
    unspecified parameters related to rectangle handling
    (bsc#901508).

  - CVE-2014-7815: The set_pixel_format function in ui/vnc.c
    allowed remote attackers to cause a denial of service
    (crash) via a small bytes_per_pixel value (bsc#902737).

  - CVE-2015-5278: Infinite loop in ne2000_receive()
    function (bsc#945989).

  - CVE-2015-7512: Buffer overflow in the pcnet_receive
    function in hw/net/pcnet.c, when a guest NIC has a
    larger MTU, allowed remote attackers to cause a denial
    of service (guest OS crash) or execute arbitrary code
    via a large packet (bsc#957162).

  - CVE-2015-8504: VNC: floating point exception
    (bsc#958491).

  - CVE-2015-8550: Paravirtualized drivers were incautious
    about shared memory contents (XSA-155) (bsc#957988).

  - CVE-2015-8554: qemu-dm buffer overrun in MSI-X handling
    (XSA-164) (bsc#958007).

  - CVE-2015-8555: Information leak in legacy x86 FPU/XMM
    initialization (XSA-165) (bsc#958009).

  - CVE-2015-8558: Infinite loop in ehci_advance_state
    resulted in DoS (bsc#959005).

  - CVE-2015-8743: ne2000: OOB memory access in ioport r/w
    functions (bsc#960725).

  - CVE-2015-8745: Reading IMR registers lead to a crash via
    assert(2) call (bsc#960707).

  - CVE-2016-1570: The PV superpage functionality in
    arch/x86/mm.c allowed local PV guests to obtain
    sensitive information, cause a denial of service, gain
    privileges, or have unspecified other impact via a
    crafted page identifier (MFN) to the (1)
    MMUEXT_MARK_SUPER or (2) MMUEXT_UNMARK_SUPER sub-op in
    the HYPERVISOR_mmuext_op hypercall or (3) unknown
    vectors related to page table updates (bsc#960861).

  - CVE-2016-1571: VMX: intercept issue with INVLPG on
    non-canonical address (XSA-168) (bsc#960862).

  - CVE-2016-1714: nvram: OOB r/w access in processing
    firmware configurations (bsc#961691).

  - CVE-2016-1981: e1000 infinite loop in start_xmit and
    e1000_receive_iov routines (bsc#963782).

  - CVE-2016-2270: Xen allowed local guest administrators to
    cause a denial of service (host reboot) via vectors
    related to multiple mappings of MMIO pages with
    different cachability settings (bsc#965315).

  - CVE-2016-2271: VMX when using an Intel or Cyrix CPU,
    allowed local HVM guest users to cause a denial of
    service (guest crash) via vectors related to a
    non-canonical RIP (bsc#965317).

  - CVE-2016-2391: usb: multiple eof_timers in ohci module
    lead to NULL pointer dereference (bsc#967013).

  - CVE-2016-2841: ne2000: Infinite loop in ne2000_receive
    (bsc#969350).

  - XSA-166: ioreq handling possibly susceptible to multiple
    read issue (bsc#958523).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=864391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=864655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=864769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=864805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=864811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=877642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=897654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=901508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=902737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=945989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=957988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=958523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=959005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960707"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=960862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=961691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=963782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=965315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=965317"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=967630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=969350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4533/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4534/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4537/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4538/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4539/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0222/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3640/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3689/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-7815/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5278/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7512/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8504/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8550/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8554/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8555/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8558/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8743/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8745/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1570/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1571/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1714/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1981/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2270/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2271/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2391/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2841/"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161154-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12440b99"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-xen-12530=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-devel-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-default-4.1.6_08_3.0.101_0.7.37-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_08_3.0.101_0.7.37-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-libs-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-tools-domU-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-doc-html-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-doc-pdf-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-libs-32bit-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-tools-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-pae-4.1.6_08_3.0.101_0.7.37-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-devel-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-default-4.1.6_08_3.0.101_0.7.37-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-trace-4.1.6_08_3.0.101_0.7.37-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-libs-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-tools-domU-4.1.6_08-26.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-pae-4.1.6_08_3.0.101_0.7.37-26.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
