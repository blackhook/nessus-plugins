#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14704-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150537);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/27");

  script_cve_id(
    "CVE-2014-3689",
    "CVE-2015-1779",
    "CVE-2020-12829",
    "CVE-2020-13361",
    "CVE-2020-13362",
    "CVE-2020-13765",
    "CVE-2020-14364",
    "CVE-2020-25084",
    "CVE-2020-25624",
    "CVE-2020-25625",
    "CVE-2020-25723",
    "CVE-2020-29130",
    "CVE-2020-29443",
    "CVE-2021-20181",
    "CVE-2021-20257"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14704-1");
  script_xref(name:"IAVB", value:"2020-B-0041-S");
  script_xref(name:"IAVB", value:"2020-B-0063-S");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"SUSE SLES11 Security Update : kvm (SUSE-SU-2021:14704-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14704-1 advisory.

  - The vmware-vga driver (hw/display/vmware_vga.c) in QEMU allows local guest users to write to qemu memory
    locations and gain privileges via unspecified parameters related to rectangle handling. (CVE-2014-3689)

  - The VNC websocket frame decoder in QEMU allows remote attackers to cause a denial of service (memory and
    CPU consumption) via a large (1) websocket payload or (2) HTTP headers section. (CVE-2015-1779)

  - In QEMU through 5.0.0, an integer overflow was found in the SM501 display driver implementation. This flaw
    occurs in the COPY_AREA macro while handling MMIO write operations through the sm501_2d_engine_write()
    callback. A local attacker could abuse this flaw to crash the QEMU process in sm501_2d_operation() in
    hw/display/sm501.c on the host, resulting in a denial of service. (CVE-2020-12829)

  - In QEMU 5.0.0 and earlier, es1370_transfer_audio in hw/audio/es1370.c does not properly validate the frame
    count, which allows guest OS users to trigger an out-of-bounds access during an es1370_write() operation.
    (CVE-2020-13361)

  - In QEMU 5.0.0 and earlier, megasas_lookup_frame in hw/scsi/megasas.c has an out-of-bounds read via a
    crafted reply_queue_head field from a guest OS user. (CVE-2020-13362)

  - rom_copy() in hw/core/loader.c in QEMU 4.0 and 4.1.0 does not validate the relationship between two
    addresses, which allows attackers to trigger an invalid memory copy operation. (CVE-2020-13765)

  - An out-of-bounds read/write access flaw was found in the USB emulator of the QEMU in versions before
    5.2.0. This issue occurs while processing USB packets from a guest when USBDevice 'setup_len' exceeds its
    'data_buf[4096]' in the do_token_in, do_token_out routines. This flaw allows a guest user to crash the
    QEMU process, resulting in a denial of service, or the potential execution of arbitrary code with the
    privileges of the QEMU process on the host. (CVE-2020-14364)

  - QEMU 5.0.0 has a use-after-free in hw/usb/hcd-xhci.c because the usb_packet_map return value is not
    checked. (CVE-2020-25084)

  - hw/usb/hcd-ohci.c in QEMU 5.0.0 has a stack-based buffer over-read via values obtained from the host
    controller driver. (CVE-2020-25624)

  - hw/usb/hcd-ohci.c in QEMU 5.0.0 has an infinite loop when a TD list has a loop. (CVE-2020-25625)

  - A reachable assertion issue was found in the USB EHCI emulation code of QEMU. It could occur while
    processing USB requests due to missing handling of DMA memory map failure. A malicious privileged user
    within the guest may abuse this flaw to send bogus USB requests and crash the QEMU process on the host,
    resulting in a denial of service. (CVE-2020-25723)

  - slirp.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29130)

  - ide_atapi_cmd_reply_end in hw/ide/atapi.c in QEMU 5.1.0 allows out-of-bounds read access because a buffer
    index is not validated. (CVE-2020-29443)

  - A race condition flaw was found in the 9pfs server implementation of QEMU up to and including 5.2.0. This
    flaw allows a malicious 9p client to cause a use-after-free error, potentially escalating their privileges
    on the system. The highest threat from this vulnerability is to confidentiality, integrity as well as
    system availability. (CVE-2021-20181)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172385");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172478");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175441");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176673");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176682");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176684");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178934");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179467");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182137");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182577");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-April/008660.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20ebf58d");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2014-3689");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-1779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-12829");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13765");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14364");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25084");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25624");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25625");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29443");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20181");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20257");
  script_set_attribute(attribute:"solution", value:
"Update the affected kvm package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20181");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'kvm-1.4.2-60.34', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'kvm-1.4.2-60.34', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kvm');
}
