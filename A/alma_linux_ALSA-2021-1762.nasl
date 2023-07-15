#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2021:1762.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157696);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2020-11947",
    "CVE-2020-16092",
    "CVE-2020-25637",
    "CVE-2020-25707",
    "CVE-2020-25723",
    "CVE-2020-27821",
    "CVE-2020-28916",
    "CVE-2020-29129",
    "CVE-2020-29130",
    "CVE-2020-29443"
  );
  script_xref(name:"ALSA", value:"2021:1762");
  script_xref(name:"IAVB", value:"2020-B-0041-S");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"AlmaLinux 8 : virt:rhel and virt-devel:rhel (ALSA-2021:1762)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2021:1762 advisory.

  - iscsi_aio_ioctl_cb in block/iscsi.c in QEMU 4.1.0 has a heap-based buffer over-read that may disclose
    unrelated information from process memory to an attacker. (CVE-2020-11947)

  - In QEMU through 5.0.0, an assertion failure can occur in the network packet processing. This issue affects
    the e1000e and vmxnet3 network devices. A malicious guest user/process could use this flaw to abort the
    QEMU process on the host, resulting in a denial of service condition in net_tx_pkt_add_raw_fragment in
    hw/net/net_tx_pkt.c. (CVE-2020-16092)

  - A double free memory issue was found to occur in the libvirt API, in versions before 6.8.0, responsible
    for requesting information about network interfaces of a running QEMU domain. This flaw affects the polkit
    access control driver. Specifically, clients connecting to the read-write socket with limited ACL
    permissions could use this flaw to crash the libvirt daemon, resulting in a denial of service, or
    potentially escalate their privileges on the system. The highest threat from this vulnerability is to data
    confidentiality and integrity as well as system availability. (CVE-2020-25637)

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

  - hw/net/e1000e_core.c in QEMU 5.0.0 has an infinite loop via an RX descriptor with a NULL buffer address.
    (CVE-2020-28916)

  - ncsi.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29129)

  - slirp.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29130)

  - ide_atapi_cmd_reply_end in hw/ide/atapi.c in QEMU 5.1.0 allows out-of-bounds read access because a buffer
    index is not validated. (CVE-2020-29443)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2021-1762.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libguestfs-winsupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libiscsi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libvirt-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nbdfuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:netcf-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ocaml-libnbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-Sys-Virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libnbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:sgabios");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/AlmaLinux/release');
if (isnull(release) || 'AlmaLinux' >!< release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
var os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var module_ver = get_kb_item('Host/AlmaLinux/appstream/virt-devel');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt-devel:rhel');
if ('rhel' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module virt-devel:' + module_ver);

var appstreams = {
    'virt-devel:rhel': [
      {'reference':'hivex-1.3.18-20.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'hivex-devel-1.3.18-20.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libguestfs-winsupport-8.2-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-1.18.0-8.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-devel-1.18.0-8.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libiscsi-utils-1.18.0-8.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-1.2.2-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnbd-devel-1.2.2-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libvirt-dbus-1.3.0-2.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nbdfuse-1.2.2-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-0.2.8-12.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-devel-0.2.8-12.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'netcf-libs-0.2.8-12.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-1.3.18-20.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-1.3.18-20.module_el8.3.0+2048+e7a0a3ea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-devel-1.3.18-20.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-hivex-devel-1.3.18-20.module_el8.3.0+2048+e7a0a3ea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libguestfs-1.40.2-27.module_el8.4.0+2358+630e803b.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libguestfs-devel-1.40.2-27.module_el8.4.0+2358+630e803b.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'ocaml-libnbd-1.2.2-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-1.2.2-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-devel-1.2.2-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ocaml-libnbd-devel-1.2.2-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-hivex-1.3.18-20.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'perl-Sys-Virt-6.0.0-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-hivex-1.3.18-20.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libnbd-1.2.2-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-libvirt-6.0.0-1.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'ruby-hivex-1.3.18-20.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'sgabios-0.20170427git-3.module_el8.3.0+2048+e7a0a3ea', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/AlmaLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach package_array ( appstreams[module] ) {
      var reference = NULL;
      var release = NULL;
      var sp = NULL;
      var cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) release = 'Alma-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && release && (!exists_check || rpm_exists(release:release, rpm:exists_check))) {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module virt-devel:rhel');

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hivex / hivex-devel / libguestfs-winsupport / libiscsi / etc');
}
