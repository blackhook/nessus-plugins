#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2022:0366-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157889);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-25020",
    "CVE-2019-15126",
    "CVE-2020-27820",
    "CVE-2021-0920",
    "CVE-2021-0935",
    "CVE-2021-3564",
    "CVE-2021-4002",
    "CVE-2021-4083",
    "CVE-2021-4135",
    "CVE-2021-4149",
    "CVE-2021-4197",
    "CVE-2021-4202",
    "CVE-2021-28711",
    "CVE-2021-28712",
    "CVE-2021-28713",
    "CVE-2021-28714",
    "CVE-2021-28715",
    "CVE-2021-33098",
    "CVE-2021-39648",
    "CVE-2021-39657",
    "CVE-2021-43975",
    "CVE-2021-43976",
    "CVE-2021-44733",
    "CVE-2021-45095",
    "CVE-2021-45486",
    "CVE-2022-0322",
    "CVE-2022-0330"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");

  script_name(english:"openSUSE 15 Security Update : kernel (openSUSE-SU-2022:0366-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2022:0366-1 advisory.

  - The BPF subsystem in the Linux kernel before 4.17 mishandles situations with a long jump over an
    instruction sequence where inner instructions require substantial expansions into multiple BPF
    instructions, leading to an overflow. This affects kernel/bpf/core.c and net/core/filter.c.
    (CVE-2018-25020)

  - An issue was discovered on Broadcom Wi-Fi client devices. Specifically timed and handcrafted traffic can
    cause internal errors (related to state transitions) in a WLAN device that lead to improper layer 2 Wi-Fi
    encryption with a consequent possibility of information disclosure over the air for a discrete set of
    traffic, a different vulnerability than CVE-2019-9500, CVE-2019-9501, CVE-2019-9502, and CVE-2019-9503.
    (CVE-2019-15126)

  - A vulnerability was found in Linux kernel, where a use-after-frees in nouveau's postclose() handler could
    happen if removing device (that is not common to remove video card physically without power-off, but same
    happens if unbind the driver). (CVE-2020-27820)

  - In unix_scm_to_skb of af_unix.c, there is a possible use after free bug due to a race condition. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-196926917References:
    Upstream kernel (CVE-2021-0920)

  - In ip6_xmit of ip6_output.c, there is a possible out of bounds write due to a use after free. This could
    lead to local escalation of privilege with System execution privileges needed. User interaction is not
    needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID: A-168607263References:
    Upstream kernel (CVE-2021-0935)

  - Rogue backends can cause DoS of guests via high frequency events T[his CNA information record relates to
    multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.] Xen offers the
    ability to run PV backends in regular unprivileged guests, typically referred to as driver domains.
    Running PV backends in driver domains has one primary security advantage: if a driver domain gets
    compromised, it doesn't have the privileges to take over the system. However, a malicious driver domain
    could try to attack other guests via sending events at a high frequency leading to a Denial of Service in
    the guest due to trying to service interrupts for elongated amounts of time. There are three affected
    backends: * blkfront patch 1, CVE-2021-28711 * netfront patch 2, CVE-2021-28712 * hvc_xen (console) patch
    3, CVE-2021-28713 (CVE-2021-28711, CVE-2021-28712, CVE-2021-28713)

  - Guest can force Linux netback driver to hog large amounts of kernel memory T[his CNA information record
    relates to multiple CVEs; the text explains which aspects/vulnerabilities correspond to which CVE.]
    Incoming data packets for a guest in the Linux kernel's netback driver are buffered until the guest is
    ready to process them. There are some measures taken for avoiding to pile up too much data, but those can
    be bypassed by the guest: There is a timeout how long the client side of an interface can stop consuming
    new packets before it is assumed to have stalled, but this timeout is rather long (60 seconds by default).
    Using a UDP connection on a fast interface can easily accumulate gigabytes of data in that time.
    (CVE-2021-28715) The timeout could even never trigger if the guest manages to have only one free slot in
    its RX queue ring page and the next package would require more than one free slot, which may be the case
    when using GSO, XDP, or software hashing. (CVE-2021-28714) (CVE-2021-28714, CVE-2021-28715)

  - Improper input validation in the Intel(R) Ethernet ixgbe driver for Linux before version 3.17.3 may allow
    an authenticated user to potentially enable denial of service via local access. (CVE-2021-33098)

  - A flaw double-free memory corruption in the Linux kernel HCI device initialization subsystem was found in
    the way user attach malicious HCI TTY Bluetooth device. A local user could use this flaw to crash the
    system. This flaw affects all the Linux kernel versions starting from 3.13. (CVE-2021-3564)

  - In gadget_dev_desc_UDC_show of configfs.c, there is a possible disclosure of kernel heap memory due to a
    race condition. This could lead to local information disclosure with System execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-160822094References: Upstream kernel (CVE-2021-39648)

  - In ufshcd_eh_device_reset_handler of ufshcd.c, there is a possible out of bounds read due to a missing
    bounds check. This could lead to local information disclosure with System execution privileges needed.
    User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-194696049References: Upstream kernel (CVE-2021-39657)

  - A flaw use-after-free in function sco_sock_sendmsg() of the Linux kernel HCI subsystem was found in the
    way user calls ioct UFFDIO_REGISTER or other way triggers race condition of the call sco_conn_del()
    together with the call sco_sock_sendmsg() with the expected controllable faulting memory page. A
    privileged local user could use this flaw to crash the system or escalate their privileges on the system.
    (CVE-2021-3640) (CVE-2021-4002)

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - A denial of service flaw for virtual machine guests in the Linux kernel's Xen hypervisor subsystem was
    found in the way users call some interrupts with high frequency from one of the guests.A local user could
    use this flaw to starve the resources resulting in a denial of service. (CVE-2021-28711) (CVE-2021-4135)

  - In the Linux kernel through 5.15.2, hw_atl_utils_fw_rpc_wait in
    drivers/net/ethernet/aquantia/atlantic/hw_atl/hw_atl_utils.c allows an attacker (who can introduce a
    crafted device) to trigger an out-of-bounds write via a crafted length value. (CVE-2021-43975)

  - In the Linux kernel through 5.15.2, mwifiex_usb_recv in drivers/net/wireless/marvell/mwifiex/usb.c allows
    an attacker (who can connect a crafted USB device) to cause a denial of service (skb_over_panic).
    (CVE-2021-43976)

  - A use-after-free exists in drivers/tee/tee_shm.c in the TEE subsystem in the Linux kernel through 5.15.11.
    This occurs because of a race condition in tee_shm_get_from_id during an attempt to free a shared memory
    object. (CVE-2021-44733)

  - pep_sock_accept in net/phonet/pep.c in the Linux kernel through 5.15.8 has a refcount leak.
    (CVE-2021-45095)

  - In the IPv4 implementation in the Linux kernel before 5.12.4, net/ipv4/route.c has an information leak
    because the hash table is very small. (CVE-2021-45486)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1071995");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1124431");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1167162");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1169514");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1172073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1184804");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185377");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186207");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189305");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189841");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190358");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191241");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191384");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192032");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192267");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192740");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192847");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193306");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193442");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193575");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193669");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193727");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193767");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193927");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194048");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194087");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194227");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194302");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194888");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195254");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CFUCZRWH2IP7FOHVYO3TO3G5PFWQXLP6/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4dcf2ef");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-25020");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-15126");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-27820");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0920");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-0935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28712");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28713");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28714");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28715");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-33098");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3564");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39648");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-39657");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4002");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4083");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4135");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4149");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4202");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43975");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-44733");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45095");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-45486");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0322");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0330");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4197");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0330");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kvmsmall-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-zfcpdump-man");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'kernel-debug-base-4.12.14-197.105.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-default-man-4.12.14-197.105.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-kvmsmall-base-4.12.14-197.105.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-vanilla-4.12.14-197.105.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-vanilla-base-4.12.14-197.105.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-vanilla-devel-4.12.14-197.105.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-vanilla-livepatch-devel-4.12.14-197.105.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-zfcpdump-man-4.12.14-197.105.1', 'cpu':'s390x', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-debug-base / kernel-default-man / kernel-kvmsmall-base / etc');
}
