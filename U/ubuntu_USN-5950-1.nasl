#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5950-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172558);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id(
    "CVE-2022-3169",
    "CVE-2022-3344",
    "CVE-2022-3435",
    "CVE-2022-3521",
    "CVE-2022-3545",
    "CVE-2022-4139",
    "CVE-2022-4379",
    "CVE-2022-45869",
    "CVE-2022-47518",
    "CVE-2022-47519",
    "CVE-2022-47520",
    "CVE-2022-47521",
    "CVE-2023-0179",
    "CVE-2023-0461",
    "CVE-2023-26605"
  );
  script_xref(name:"USN", value:"5950-1");

  script_name(english:"Ubuntu 22.10 : Linux kernel (KVM) vulnerabilities (USN-5950-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 22.10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
USN-5950-1 advisory.

  - A flaw was found in the Linux kernel. A denial of service flaw may occur if there is a consecutive request
    of the NVME_IOCTL_RESET and the NVME_IOCTL_SUBSYS_RESET through the device file of the driver, resulting
    in a PCIe link disconnect. (CVE-2022-3169)

  - A flaw was found in the KVM's AMD nested virtualization (SVM). A malicious L1 guest could purposely fail
    to intercept the shutdown of a cooperative nested guest (L2), possibly leading to a page fault and kernel
    panic in the host (L0). (CVE-2022-3344)

  - A vulnerability classified as problematic has been found in Linux Kernel. This affects the function
    fib_nh_match of the file net/ipv4/fib_semantics.c of the component IPv4 Handler. The manipulation leads to
    out-of-bounds read. It is possible to initiate the attack remotely. It is recommended to apply a patch to
    fix this issue. The identifier VDB-210357 was assigned to this vulnerability. (CVE-2022-3435)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function kcm_tx_work of the file net/kcm/kcmsock.c of the component kcm. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211018 is the identifier
    assigned to this vulnerability. (CVE-2022-3521)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - An incorrect TLB flush issue was found in the Linux kernel's GPU i915 kernel driver, potentially leading
    to random memory corruption or data leaks. This flaw could allow a local user to crash the system or
    escalate their privileges on the system. (CVE-2022-4139)

  - A use-after-free vulnerability was found in __nfs42_ssc_open() in fs/nfs/nfs4file.c in the Linux kernel.
    This flaw allows an attacker to conduct a remote denial (CVE-2022-4379)

  - A race condition in the x86 KVM subsystem in the Linux kernel through 6.1-rc6 allows guest OS users to
    cause a denial of service (host OS crash or host OS memory corruption) when nested virtualisation and the
    TDP MMU are enabled. (CVE-2022-45869)

  - An issue was discovered in the Linux kernel before 6.0.11. Missing validation of the number of channels in
    drivers/net/wireless/microchip/wilc1000/cfg80211.c in the WILC1000 wireless driver can trigger a heap-
    based buffer overflow when copying the list of operating channels from Wi-Fi management frames.
    (CVE-2022-47518)

  - An issue was discovered in the Linux kernel before 6.0.11. Missing validation of
    IEEE80211_P2P_ATTR_OPER_CHANNEL in drivers/net/wireless/microchip/wilc1000/cfg80211.c in the WILC1000
    wireless driver can trigger an out-of-bounds write when parsing the channel list attribute from Wi-Fi
    management frames. (CVE-2022-47519)

  - An issue was discovered in the Linux kernel before 6.0.11. Missing offset validation in
    drivers/net/wireless/microchip/wilc1000/hif.c in the WILC1000 wireless driver can trigger an out-of-bounds
    read when parsing a Robust Security Network (RSN) information element from a Netlink packet.
    (CVE-2022-47520)

  - An issue was discovered in the Linux kernel before 6.0.11. Missing validation of
    IEEE80211_P2P_ATTR_CHANNEL_LIST in drivers/net/wireless/microchip/wilc1000/cfg80211.c in the WILC1000
    wireless driver can trigger a heap-based buffer overflow when parsing the operating channel attribute from
    Wi-Fi management frames. (CVE-2022-47521)

  - There is a use-after-free vulnerability in the Linux Kernel which can be exploited to achieve local
    privilege escalation. To reach the vulnerability kernel configuration flag CONFIG_TLS or
    CONFIG_XFRM_ESPINTCP has to be configured, but the operation does not require any privilege. There is a
    use-after-free bug of icsk_ulp_data of a struct inet_connection_sock. When CONFIG_TLS is enabled, user can
    install a tls context (struct tls_context) on a connected tcp socket. The context is not cleared if this
    socket is disconnected and reused as a listener. If a new socket is created from the listener, the context
    is inherited and vulnerable. The setsockopt TCP_ULP operation does not require any privilege. We recommend
    upgrading past commit 2c02d41d71f90a5168391b6a5f2954112ba2307c (CVE-2023-0461)

  - In the Linux kernel 6.0.8, there is a use-after-free in inode_cgwb_move_to_attached in fs/fs-writeback.c,
    related to __list_del_entry_valid. (CVE-2023-26605)

  - kernel: Netfilter integer overflow vulnerability in nft_payload_copy_vlan (CVE-2023-0179)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5950-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-26605");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.19.0-1019-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! preg(pattern:"^(22\.10)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 22.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var machine_kernel_release = get_kb_item_or_exit('Host/uname-r');
if (machine_kernel_release)
{
  if (! preg(pattern:"^((5.19.0-\d+-kvm))$", string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);
  var extra = '';
  var kernel_mappings = {
    "5.19.0-\d+-kvm" : "5.19.0-1019"
  };
  var trimmed_kernel_release = ereg_replace(string:machine_kernel_release, pattern:"(-\D.*?)$", replace:'');
  foreach var kernel_regex (keys(kernel_mappings)) {
    if (preg(pattern:kernel_regex, string:machine_kernel_release)) {
      if (deb_ver_cmp(ver1:trimmed_kernel_release, ver2:kernel_mappings[kernel_regex]) < 0)
      {
        extra = extra + 'Running Kernel level of ' + trimmed_kernel_release + ' does not meet the minimum fixed level of ' + kernel_mappings[kernel_regex] + ' for this advisory.\n\n';
      }
      else
      {
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5950-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-3169', 'CVE-2022-3344', 'CVE-2022-3435', 'CVE-2022-3521', 'CVE-2022-3545', 'CVE-2022-4139', 'CVE-2022-4379', 'CVE-2022-45869', 'CVE-2022-47518', 'CVE-2022-47519', 'CVE-2022-47520', 'CVE-2022-47521', 'CVE-2023-0179', 'CVE-2023-0461', 'CVE-2023-26605');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5950-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
