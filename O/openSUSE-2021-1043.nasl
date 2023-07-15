#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1043-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151619);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2019-15890",
    "CVE-2020-8608",
    "CVE-2020-10756",
    "CVE-2020-14364",
    "CVE-2020-25085",
    "CVE-2020-25707",
    "CVE-2020-25723",
    "CVE-2020-29129",
    "CVE-2020-29130",
    "CVE-2021-3419",
    "CVE-2021-3544",
    "CVE-2021-3545",
    "CVE-2021-3546",
    "CVE-2021-20257"
  );
  script_xref(name:"IAVB", value:"2020-B-0063-S");
  script_xref(name:"IAVB", value:"2020-B-0075-S");

  script_name(english:"openSUSE 15 Security Update : qemu (openSUSE-SU-2021:1043-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1043-1 advisory.

  - libslirp 4.0.0, as used in QEMU 4.1.0, has a use-after-free in ip_reass in ip_input.c. (CVE-2019-15890)

  - An out-of-bounds read vulnerability was found in the SLiRP networking implementation of the QEMU emulator.
    This flaw occurs in the icmp6_send_echoreply() routine while replying to an ICMP echo request, also known
    as ping. This flaw allows a malicious guest to leak the contents of the host memory, resulting in possible
    information disclosure. This flaw affects versions of libslirp before 4.3.1. (CVE-2020-10756)

  - An out-of-bounds read/write access flaw was found in the USB emulator of the QEMU in versions before
    5.2.0. This issue occurs while processing USB packets from a guest when USBDevice 'setup_len' exceeds its
    'data_buf[4096]' in the do_token_in, do_token_out routines. This flaw allows a guest user to crash the
    QEMU process, resulting in a denial of service, or the potential execution of arbitrary code with the
    privileges of the QEMU process on the host. (CVE-2020-14364)

  - QEMU 5.0.0 has a heap-based Buffer Overflow in flatview_read_continue in exec.c because hw/sd/sdhci.c
    mishandles a write operation in the SDHC_BLKSIZE case. (CVE-2020-25085)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. Reason: This candidate is a duplicate of CVE-2020-28916
    (CVE-2020-25707)

  - A reachable assertion issue was found in the USB EHCI emulation code of QEMU. It could occur while
    processing USB requests due to missing handling of DMA memory map failure. A malicious privileged user
    within the guest may abuse this flaw to send bogus USB requests and crash the QEMU process on the host,
    resulting in a denial of service. (CVE-2020-25723)

  - ncsi.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29129)

  - slirp.c in libslirp through 4.3.1 has a buffer over-read because it tries to read a certain amount of
    header data even if that exceeds the total packet length. (CVE-2020-29130)

  - In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c misuses snprintf return values, leading to a buffer
    overflow in later code. (CVE-2020-8608)

  - ** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. Reason: This candidate was withdrawn by
    its CNA. Notes: none. (CVE-2021-3419)

  - Several memory leaks were found in the virtio vhost-user GPU device (vhost-user-gpu) of QEMU in versions
    up to and including 6.0. They exist in contrib/vhost-user-gpu/vhost-user-gpu.c and contrib/vhost-user-
    gpu/virgl.c due to improper release of memory (i.e., free) after effective lifetime. (CVE-2021-3544)

  - An information disclosure vulnerability was found in the virtio vhost-user GPU device (vhost-user-gpu) of
    QEMU in versions up to and including 6.0. The flaw exists in virgl_cmd_get_capset_info() in contrib/vhost-
    user-gpu/virgl.c and could occur due to the read of uninitialized memory. A malicious guest could exploit
    this issue to leak memory from the host. (CVE-2021-3545)

  - A flaw was found in vhost-user-gpu of QEMU in versions up to and including 6.0. An out-of-bounds write
    vulnerability can allow a malicious guest to crash the QEMU process on the host resulting in a denial of
    service or potentially execute arbitrary code on the host with the privileges of the QEMU process. The
    highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2021-3546)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1149813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1163019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1175534");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178683");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179477");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179484");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183979");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184574");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185591");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185981");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185990");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186290");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187013");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SVDDMT7IUGYOEFTYO3UWD73PJMJL4FSY/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d042d76e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-10756");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-14364");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25723");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29129");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-29130");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8608");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-20257");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3419");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3546");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8608");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3546");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-audio-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ksm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-microvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-sdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ui-spice-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vhost-user-gpu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
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
release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

pkgs = [
    {'reference':'qemu-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-arm-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-alsa-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-pa-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-audio-sdl-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-curl-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-dmg-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-gluster-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-iscsi-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-nfs-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-rbd-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-block-ssh-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-extra-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-guest-agent-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ipxe-1.0.0+-lp152.9.16.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ksm-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-kvm-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-lang-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-linux-user-4.2.1-lp152.9.16.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-microvm-4.2.1-lp152.9.16.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ppc-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-s390-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-seabios-1.12.1+-lp152.9.16.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-sgabios-8-lp152.9.16.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-testsuite-4.2.1-lp152.9.16.7', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-tools-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-curses-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-gtk-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-sdl-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-ui-spice-app-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-vgabios-1.12.1+-lp152.9.16.2', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-vhost-user-gpu-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'qemu-x86-4.2.1-lp152.9.16.2', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  cpu = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'qemu / qemu-arm / qemu-audio-alsa / qemu-audio-pa / qemu-audio-sdl / etc');
}
