#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:1942-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150736);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2019-15890",
    "CVE-2020-8608",
    "CVE-2020-14364",
    "CVE-2020-17380",
    "CVE-2020-25085",
    "CVE-2020-25707",
    "CVE-2020-25723",
    "CVE-2020-27821",
    "CVE-2020-29129",
    "CVE-2020-29130",
    "CVE-2021-3409",
    "CVE-2021-3416",
    "CVE-2021-3419",
    "CVE-2021-20263"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:1942-1");
  script_xref(name:"IAVB", value:"2020-B-0063-S");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : qemu (SUSE-SU-2021:1942-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2021:1942-1 advisory.

  - libslirp 4.0.0, as used in QEMU 4.1.0, has a use-after-free in ip_reass in ip_input.c. (CVE-2019-15890)

  - An out-of-bounds read/write access flaw was found in the USB emulator of the QEMU in versions before
    5.2.0. This issue occurs while processing USB packets from a guest when USBDevice 'setup_len' exceeds its
    'data_buf[4096]' in the do_token_in, do_token_out routines. This flaw allows a guest user to crash the
    QEMU process, resulting in a denial of service, or the potential execution of arbitrary code with the
    privileges of the QEMU process on the host. (CVE-2020-14364)

  - A heap-based buffer overflow was found in QEMU through 5.0.0 in the SDHCI device emulation support. It
    could occur while doing a multi block SDMA transfer via the sdhci_sdma_transfer_multi_blocks() routine in
    hw/sd/sdhci.c. A guest user or process could use this flaw to crash the QEMU process on the host,
    resulting in a denial of service condition, or potentially execute arbitrary code with privileges of the
    QEMU process on the host. (CVE-2020-17380)

  - QEMU 5.0.0 has a heap-based Buffer Overflow in flatview_read_continue in exec.c because hw/sd/sdhci.c
    mishandles a write operation in the SDHC_BLKSIZE case. (CVE-2020-25085)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. Reason: This candidate is a duplicate of CVE-2020-28916
    (CVE-2020-25707)

  - A reachable assertion issue was found in the USB EHCI emulation code of QEMU. It could occur while
    processing USB requests due to missing handling of DMA memory map failure. A malicious privileged user
    within the guest may abuse this flaw to send bogus USB requests and crash the QEMU process on the host,
    resulting in a denial of service. (CVE-2020-25723)

  - A flaw was found in the memory management API of QEMU during the initialization of a memory region cache.
    This issue could lead to an out-of-bounds write access to the MSI-X table while performing MMIO
    operations. A guest user may abuse this flaw to crash the QEMU process on the host, resulting in a denial
    of service. This flaw affects QEMU versions prior to 5.2.0. (CVE-2020-27821)

  - ncsi.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29129)

  - slirp.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29130)

  - In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c misuses snprintf return values, leading to a buffer
    overflow in later code. (CVE-2020-8608)

  - A flaw was found in the virtio-fs shared file system daemon (virtiofsd) of QEMU. The new 'xattrmap' option
    may cause the 'security.capability' xattr in the guest to not drop on file write, potentially leading to a
    modified, privileged executable in the guest. In rare circumstances, this flaw could be used by a
    malicious user to elevate their privileges within the guest. (CVE-2021-20263)

  - The patch for CVE-2020-17380/CVE-2020-25085 was found to be ineffective, thus making QEMU vulnerable to
    the out-of-bounds read/write access issues previously found in the SDHCI controller emulation code. This
    flaw allows a malicious privileged guest to crash the QEMU process on the host, resulting in a denial of
    service or potential code execution. QEMU up to (including) 5.2.0 is affected by this. (CVE-2021-3409)

  - A potential stack overflow via infinite loop issue was found in various NIC emulators of QEMU in versions
    up to and including 5.2.0. The issue occurs in loopback mode of a NIC wherein reentrant DMA checks get
    bypassed. A guest user/process may use this flaw to consume CPU cycles or crash the QEMU process on the
    host resulting in DoS scenario. (CVE-2021-3416)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by
    its CNA. Notes: none. (CVE-2021-3419)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1163019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175144");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179686");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182282");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182968");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183373");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186290");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-June/008986.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b594ec1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14364");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-17380");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27821");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29129");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20263");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3409");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3416");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3419");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8608");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-17380");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-audio-spice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-chardev-baum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-chardev-spice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-hw-display-qxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-hw-display-virtio-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-hw-display-virtio-gpu-pci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-hw-display-virtio-vga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-hw-s390x-virtio-gpu-ccw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-hw-usb-redirect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ksm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-skiboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-spice-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-ui-spice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

var sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + sp);
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + sp);

var pkgs = [
    {'reference':'qemu-tools-5.2.0-17', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'qemu-tools-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-basesystem-release-15.3'},
    {'reference':'qemu-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-arm-5.2.0-17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-audio-alsa-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-audio-pa-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-audio-spice-5.2.0-17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-audio-spice-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-block-curl-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-block-iscsi-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-block-rbd-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-block-ssh-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-chardev-baum-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-chardev-spice-5.2.0-17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-chardev-spice-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-guest-agent-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-hw-display-qxl-5.2.0-17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-hw-display-qxl-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-hw-display-virtio-gpu-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-hw-display-virtio-gpu-pci-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-hw-display-virtio-vga-5.2.0-17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-hw-display-virtio-vga-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-hw-s390x-virtio-gpu-ccw-5.2.0-17', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-hw-usb-redirect-5.2.0-17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-hw-usb-redirect-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ipxe-1.0.0+-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ksm-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-kvm-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-lang-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-s390x-5.2.0-17', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-seabios-1.14.0_0_g155821a-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-sgabios-8-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-skiboot-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ui-curses-5.2.0-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ui-gtk-5.2.0-17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ui-gtk-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ui-opengl-5.2.0-17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ui-opengl-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ui-spice-app-5.2.0-17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ui-spice-app-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ui-spice-core-5.2.0-17', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-ui-spice-core-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-vgabios-1.14.0_0_g155821a-17', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'},
    {'reference':'qemu-x86-5.2.0-17', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sle-module-server-applications-release-15.3'}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var sp = NULL;
  var cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (exists_check) {
      if (!rpm_exists(release:release, rpm:exists_check)) continue;
      if ('ltss' >< tolower(exists_check)) ltss_caveat_required = TRUE;
    }
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-arm / qemu-audio-alsa / qemu-audio-pa / qemu-audio-spice / etc');
}
