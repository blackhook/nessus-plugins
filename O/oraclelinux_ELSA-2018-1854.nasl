#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2018-1854.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(110701);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/08");

  script_cve_id(
    "CVE-2012-6701",
    "CVE-2015-8830",
    "CVE-2016-8650",
    "CVE-2017-2671",
    "CVE-2017-6001",
    "CVE-2017-7308",
    "CVE-2017-7616",
    "CVE-2017-7889",
    "CVE-2017-8890",
    "CVE-2017-9075",
    "CVE-2017-9076",
    "CVE-2017-9077",
    "CVE-2017-12190",
    "CVE-2017-15121",
    "CVE-2017-18203",
    "CVE-2018-1130",
    "CVE-2018-3639",
    "CVE-2018-5803"
  );
  script_xref(name:"RHSA", value:"2018:1854");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2018-1854)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2018-1854 advisory.

  - The mpi_powm function in lib/mpi/mpi-pow.c in the Linux kernel through 4.8.11 does not ensure that memory
    is allocated for limb data, which allows local users to cause a denial of service (stack memory corruption
    and panic) via an add_key system call for an RSA key with a zero exponent. (CVE-2016-8650)

  - Race condition in kernel/events/core.c in the Linux kernel before 4.9.7 allows local users to gain
    privileges via a crafted application that makes concurrent perf_event_open system calls for moving a
    software group into a hardware context. NOTE: this vulnerability exists because of an incomplete fix for
    CVE-2016-6786. (CVE-2017-6001)

  - The inet_csk_clone_lock function in net/ipv4/inet_connection_sock.c in the Linux kernel through 4.10.15
    allows attackers to cause a denial of service (double free) or possibly have unspecified other impact by
    leveraging use of the accept system call. (CVE-2017-8890)

  - The packet_set_ring function in net/packet/af_packet.c in the Linux kernel through 4.10.6 does not
    properly validate certain block-size data, which allows local users to cause a denial of service (integer
    signedness error and out-of-bounds write), or gain privileges (if the CAP_NET_RAW capability is held), via
    crafted system calls. (CVE-2017-7308)

  - The tcp_v6_syn_recv_sock function in net/ipv6/tcp_ipv6.c in the Linux kernel through 4.11.1 mishandles
    inheritance, which allows local users to cause a denial of service or possibly have unspecified other
    impact via crafted system calls, a related issue to CVE-2017-8890. (CVE-2017-9077)

  - The ping_unhash function in net/ipv4/ping.c in the Linux kernel through 4.10.8 is too late in obtaining a
    certain lock and consequently cannot ensure that disconnect function calls are safe, which allows local
    users to cause a denial of service (panic) by leveraging access to the protocol value of IPPROTO_ICMP in a
    socket system call. (CVE-2017-2671)

  - Incorrect error handling in the set_mempolicy and mbind compat syscalls in mm/mempolicy.c in the Linux
    kernel through 4.10.9 allows local users to obtain sensitive information from uninitialized stack data by
    triggering failure of a certain bitmap operation. (CVE-2017-7616)

  - The mm subsystem in the Linux kernel through 3.2 does not properly enforce the CONFIG_STRICT_DEVMEM
    protection mechanism, which allows local users to read or write to kernel memory locations in the first
    megabyte (and bypass slab-allocation access restrictions) via an application that opens the /dev/mem file,
    related to arch/x86/mm/init.c and drivers/char/mem.c. (CVE-2017-7889)

  - The dccp_v6_request_recv_sock function in net/dccp/ipv6.c in the Linux kernel through 4.11.1 mishandles
    inheritance, which allows local users to cause a denial of service or possibly have unspecified other
    impact via crafted system calls, a related issue to CVE-2017-8890. (CVE-2017-9076)

  - The sctp_v6_create_accept_sk function in net/sctp/ipv6.c in the Linux kernel through 4.11.1 mishandles
    inheritance, which allows local users to cause a denial of service or possibly have unspecified other
    impact via crafted system calls, a related issue to CVE-2017-8890. (CVE-2017-9075)

  - The bio_map_user_iov and bio_unmap_user functions in block/bio.c in the Linux kernel before 4.13.8 do
    unbalanced refcounting when a SCSI I/O vector has small consecutive buffers belonging to the same page.
    The bio_add_pc_page function merges them into one, but the page reference is never dropped. This causes a
    memory leak and possible system lockup (exploitable against the host OS by a guest OS user, if a SCSI disk
    is passed through to a virtual machine) due to an out-of-memory condition. (CVE-2017-12190)

  - A non-privileged user is able to mount a fuse filesystem on RHEL 6 or 7 and crash a system if an
    application punches a hole in a file that does not end aligned to a page boundary. (CVE-2017-15121)

  - The dm_get_from_kobject function in drivers/md/dm.c in the Linux kernel before 4.14.3 allow local users to
    cause a denial of service (BUG) by leveraging a race condition with __dm_destroy during creation and
    removal of DM devices. (CVE-2017-18203)

  - Systems with microprocessors utilizing speculative execution and speculative execution of memory reads
    before the addresses of all prior memory writes are known may allow unauthorized disclosure of information
    to an attacker with local user access via a side-channel analysis, aka Speculative Store Bypass (SSB),
    Variant 4. (CVE-2018-3639)

  - Integer overflow in fs/aio.c in the Linux kernel before 3.4.1 allows local users to cause a denial of
    service or possibly have unspecified other impact via a large AIO iovec. (CVE-2012-6701)

  - Integer overflow in the aio_setup_single_vector function in fs/aio.c in the Linux kernel 4.0 allows local
    users to cause a denial of service or possibly have unspecified other impact via a large AIO iovec. NOTE:
    this vulnerability exists because of a CVE-2012-6701 regression. (CVE-2015-8830)

  - In the Linux Kernel before version 4.15.8, 4.14.25, 4.9.87, 4.4.121, 4.1.51, and 3.2.102, an error in the
    _sctp_make_chunk() function (net/sctp/sm_make_chunk.c) when handling SCTP packets length can be
    exploited to cause a kernel crash. (CVE-2018-5803)

  - Linux kernel before version 4.16-rc7 is vulnerable to a null pointer dereference in dccp_write_xmit()
    function in net/dccp/output.c in that allows a local user to cause a denial of service by a number of
    certain crafted system calls. (CVE-2018-1130)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2018-1854.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6001");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AF_PACKET packet_set_ring Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
var os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.32-754.el6'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2018-1854');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '2.6';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-2.6.32-754.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-2.6.32-754.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.32'},
    {'reference':'kernel-abi-whitelists-2.6.32-754.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-abi-whitelists-2.6.32'},
    {'reference':'kernel-debug-2.6.32-754.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-2.6.32-754.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-754.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-debug-devel-2.6.32-754.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-754.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-devel-2.6.32-754.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.32'},
    {'reference':'kernel-firmware-2.6.32-754.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-firmware-2.6.32'},
    {'reference':'kernel-headers-2.6.32-754.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'kernel-headers-2.6.32-754.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.32'},
    {'reference':'perf-2.6.32-754.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perf-2.6.32-754.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-754.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-perf-2.6.32-754.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['release'])) release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && release) {
    if (exists_check) {
        if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-abi-whitelists / kernel-debug / etc');
}
