##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2021-9034.
##

include('compat.inc');

if (description)
{
  script_id(146269);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2019-15034",
    "CVE-2020-10702",
    "CVE-2020-10756",
    "CVE-2020-11102",
    "CVE-2020-12829",
    "CVE-2020-13253",
    "CVE-2020-13362",
    "CVE-2020-13659",
    "CVE-2020-13754",
    "CVE-2020-13791",
    "CVE-2020-14364",
    "CVE-2020-14415",
    "CVE-2020-15863",
    "CVE-2020-16092",
    "CVE-2020-25084",
    "CVE-2020-25624",
    "CVE-2020-25625",
    "CVE-2020-25723",
    "CVE-2020-27616",
    "CVE-2020-28916",
    "CVE-2020-29129",
    "CVE-2020-29130"
  );

  script_name(english:"Oracle Linux 7 : qemu (ELSA-2021-9034)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2021-9034 advisory.

  - An out-of-bounds read/write access flaw was found in the USB emulator of the QEMU in versions before
    5.2.0. This issue occurs while processing USB packets from a guest when USBDevice 'setup_len' exceeds its
    'data_buf[4096]' in the do_token_in, do_token_out routines. This flaw allows a guest user to crash the
    QEMU process, resulting in a denial of service, or the potential execution of arbitrary code with the
    privileges of the QEMU process on the host. (CVE-2020-14364)

  - In QEMU through 5.0.0, an assertion failure can occur in the network packet processing. This issue affects
    the e1000e and vmxnet3 network devices. A malicious guest user/process could use this flaw to abort the
    QEMU process on the host, resulting in a denial of service condition in net_tx_pkt_add_raw_fragment in
    hw/net/net_tx_pkt.c. (CVE-2020-16092)

  - hw/pci/msix.c in QEMU 4.2.0 allows guest OS users to trigger an out-of-bounds access via a crafted address
    in an msi-x mmio operation. (CVE-2020-13754)

  - In QEMU 5.0.0 and earlier, megasas_lookup_frame in hw/scsi/megasas.c has an out-of-bounds read via a
    crafted reply_queue_head field from a guest OS user. (CVE-2020-13362)

  - hw/net/tulip.c in QEMU 4.2.0 has a buffer overflow during the copying of tx/rx buffers because the frame
    size is not validated against the r/w data length. (CVE-2020-11102)

  - hw/net/xgmac.c in the XGMAC Ethernet controller in QEMU before 07-20-2020 has a buffer overflow. This
    occurs during packet transmission and affects the highbank and midway emulated machines. A guest user or
    process could use this flaw to crash the QEMU process on the host, resulting in a denial of service or
    potential privileged code execution. This was fixed in commit 5519724a13664b43e225ca05351c60b4468e4555.
    (CVE-2020-15863)

  - hw/pci/pci.c in QEMU 4.2.0 allows guest OS users to trigger an out-of-bounds access by providing an
    address near the end of the PCI configuration space. (CVE-2020-13791)

  - address_space_map in exec.c in QEMU 4.2.0 can trigger a NULL pointer dereference related to BounceBuffer.
    (CVE-2020-13659)

  - sd_wp_addr in hw/sd/sd.c in QEMU 4.2.0 uses an unvalidated address, which leads to an out-of-bounds read
    during sdhci_write() operations. A guest OS user can crash the QEMU process. (CVE-2020-13253)

  - A flaw was found in QEMU in the implementation of the Pointer Authentication (PAuth) support for ARM
    introduced in version 4.0 and fixed in version 5.0.0. A general failure of the signature generation
    process caused every PAuth-enforced pointer to be signed with the same signature. A local attacker could
    obtain the signature of a protected pointer and abuse this flaw to bypass PAuth protection for all
    programs running on QEMU. (CVE-2020-10702)

  - hw/display/bochs-display.c in QEMU 4.0.0 does not ensure a sufficient PCI config space allocation, leading
    to a buffer overflow involving the PCIe extended config space. (CVE-2019-15034)

  - In QEMU through 5.0.0, an integer overflow was found in the SM501 display driver implementation. This flaw
    occurs in the COPY_AREA macro while handling MMIO write operations through the sm501_2d_engine_write()
    callback. A local attacker could abuse this flaw to crash the QEMU process in sm501_2d_operation() in
    hw/display/sm501.c on the host, resulting in a denial of service. (CVE-2020-12829)

  - oss_write in audio/ossaudio.c in QEMU before 5.0.0 mishandles a buffer position. (CVE-2020-14415)

  - hw/usb/hcd-ohci.c in QEMU 5.0.0 has an infinite loop when a TD list has a loop. (CVE-2020-25625)

  - QEMU 5.0.0 has a use-after-free in hw/usb/hcd-xhci.c because the usb_packet_map return value is not
    checked. (CVE-2020-25084)

  - ati_2d_blt in hw/display/ati_2d.c in QEMU 4.2.1 can encounter an outside-limits situation in a
    calculation. A guest can crash the QEMU process. (CVE-2020-27616)

  - ncsi.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29129)

  - slirp.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29130)

  - hw/usb/hcd-ohci.c in QEMU 5.0.0 has a stack-based buffer over-read via values obtained from the host
    controller driver. (CVE-2020-25624)

  - hw/net/e1000e_core.c in QEMU 5.0.0 has an infinite loop via an RX descriptor with a NULL buffer address.
    (CVE-2020-28916)

  - An out-of-bounds read vulnerability was found in the SLiRP networking implementation of the QEMU emulator.
    This flaw occurs in the icmp6_send_echoreply() routine while replying to an ICMP echo request, also known
    as ping. This flaw allows a malicious guest to leak the contents of the host memory, resulting in possible
    information disclosure. This flaw affects versions of libslirp before 4.3.1. (CVE-2020-10756)

  - A reachable assertion issue was found in the USB EHCI emulation code of QEMU. It could occur while
    processing USB requests due to missing handling of DMA memory map failure. A malicious privileged user
    within the guest may abuse this flaw to send bogus USB requests and crash the QEMU process on the host,
    resulting in a denial of service. (CVE-2020-25723)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2021-9034.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11102");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13754");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-kvm-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qemu-system-x86-core");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

pkgs = [
    {'reference':'qemu-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-block-gluster-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-block-gluster-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-block-iscsi-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-block-iscsi-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-block-rbd-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-block-rbd-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-common-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-common-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-img-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-img-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-kvm-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-kvm-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-kvm-core-4.2.1-4.el7', 'cpu':'aarch64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-kvm-core-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-system-x86-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'15'},
    {'reference':'qemu-system-x86-core-4.2.1-4.el7', 'cpu':'x86_64', 'release':'7', 'epoch':'15'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  rpm_prefix = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['rpm_prefix'])) rpm_prefix = package_array['rpm_prefix'];
  if (reference && release) {
    if (rpm_prefix) {
        if (rpm_exists(release:release, rpm:rpm_prefix) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-block-gluster / qemu-block-iscsi / etc');
}