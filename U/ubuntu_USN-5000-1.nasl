#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5000-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150957);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-26139",
    "CVE-2020-26141",
    "CVE-2020-26145",
    "CVE-2020-26147",
    "CVE-2021-3506",
    "CVE-2021-3609",
    "CVE-2021-23133",
    "CVE-2021-23134",
    "CVE-2021-31829",
    "CVE-2021-32399",
    "CVE-2021-33034",
    "CVE-2021-33200"
  );
  script_xref(name:"USN", value:"5000-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-5000-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5000-1 advisory.

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that received fragments be cleared from memory after (re)connecting to a
    network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP,
    CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or exfiltrate user data.
    (CVE-2020-24586)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that all fragments of a frame are encrypted under the same key. An adversary
    can abuse this to decrypt selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP encryption key is periodically renewed. (CVE-2020-24587)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated.
    Against devices that support receiving non-SSP A-MSDU frames (which is mandatory as part of 802.11n), an
    adversary can abuse this to inject arbitrary network packets. (CVE-2020-24588)

  - An issue was discovered in the kernel in NetBSD 7.1. An Access Point (AP) forwards EAPOL frames to other
    clients even though the sender has not yet successfully authenticated to the AP. This might be abused in
    projected Wi-Fi networks to launch denial-of-service attacks against connected clients and makes it easier
    to exploit other vulnerabilities in connected clients. (CVE-2020-26139)

  - An issue was discovered in the ALFA Windows 10 driver 6.1316.1209 for AWUS036H. The Wi-Fi implementation
    does not verify the Message Integrity Check (authenticity) of fragmented TKIP frames. An adversary can
    abuse this to inject and possibly decrypt packets in WPA or WPA2 networks that support the TKIP data-
    confidentiality protocol. (CVE-2020-26141)

  - An issue was discovered on Samsung Galaxy S3 i9305 4.4.4 devices. The WEP, WPA, WPA2, and WPA3
    implementations accept second (or subsequent) broadcast fragments even when sent in plaintext and process
    them as full unfragmented frames. An adversary can abuse this to inject arbitrary network packets
    independent of the network configuration. (CVE-2020-26145)

  - An issue was discovered in the Linux kernel 5.8.9. The WEP, WPA, WPA2, and WPA3 implementations reassemble
    fragments even though some of them were sent in plaintext. This vulnerability can be abused to inject
    packets and/or exfiltrate selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP data-confidentiality protocol is used. (CVE-2020-26147)

  - An out-of-bounds (OOB) memory access flaw was found in fs/f2fs/node.c in the f2fs module in the Linux
    kernel in versions before 5.12.0-rc4. A bounds check failure allows a local attacker to gain access to
    out-of-bounds memory leading to a system crash or a leak of internal kernel information. The highest
    threat from this vulnerability is to system availability. (CVE-2021-3506)

  - A race condition in Linux kernel SCTP sockets (net/sctp/socket.c) before 5.12-rc8 can lead to kernel
    privilege escalation from the context of a network service or an unprivileged process. If
    sctp_destroy_sock is called without sock_net(sk)->sctp.addr_wq_lock then an element is removed from the
    auto_asconf_splist list without any proper locking. This can be exploited by an attacker with network
    service privileges to escalate to root or from the context of an unprivileged user directly if a
    BPF_CGROUP_INET_SOCK_CREATE is attached which denies creation of some SCTP socket. (CVE-2021-23133)

  - Use After Free vulnerability in nfc sockets in the Linux Kernel before 5.12.4 allows local attackers to
    elevate their privileges. In typical configurations, the issue can only be triggered by a privileged local
    user with the CAP_NET_RAW capability. (CVE-2021-23134)

  - kernel/bpf/verifier.c in the Linux kernel through 5.12.1 performs undesirable speculative loads, leading
    to disclosure of stack content via side-channel attacks, aka CID-801c6058d14a. The specific concern is not
    protecting the BPF stack area against speculative loads. Also, the BPF stack can contain uninitialized
    data that might represent sensitive information previously operated on by the kernel. (CVE-2021-31829)

  - net/bluetooth/hci_request.c in the Linux kernel through 5.12.2 has a race condition for removal of the HCI
    controller. (CVE-2021-32399)

  - In the Linux kernel before 5.12.4, net/bluetooth/hci_event.c has a use-after-free when destroying an
    hci_chan, aka CID-5c4c8c954409. This leads to writing an arbitrary value. (CVE-2021-33034)

  - kernel/bpf/verifier.c in the Linux kernel through 5.12.7 enforces incorrect limits for pointer arithmetic
    operations, aka CID-bb01a1bba579. This can be abused to perform out-of-bounds reads and writes in kernel
    memory, leading to local privilege escalation to root. In particular, there is a corner case where the off
    reg causes a masking direction change, which then results in an incorrect final aux->alu_limit.
    (CVE-2021-33200)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5000-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33200");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1018-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1038-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1046-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1046-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1048-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1051-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1051-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-77-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-77-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-77-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop-5.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-20.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2021-2023 Canonical, Inc. / NASL script (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-24586', 'CVE-2020-24587', 'CVE-2020-24588', 'CVE-2020-26139', 'CVE-2020-26141', 'CVE-2020-26145', 'CVE-2020-26147', 'CVE-2021-3506', 'CVE-2021-3609', 'CVE-2021-23133', 'CVE-2021-23134', 'CVE-2021-31829', 'CVE-2021-32399', 'CVE-2021-33034', 'CVE-2021-33200');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5000-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1018-gkeop', 'pkgver': '5.4.0-1018.19~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1038-raspi', 'pkgver': '5.4.0-1038.41~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1046-gcp', 'pkgver': '5.4.0-1046.49~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1046-gke', 'pkgver': '5.4.0-1046.48~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1048-oracle', 'pkgver': '5.4.0-1048.52~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1051-aws', 'pkgver': '5.4.0-1051.53~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-1051-azure', 'pkgver': '5.4.0-1051.53~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-77-generic', 'pkgver': '5.4.0-77.86~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-77-generic-lpae', 'pkgver': '5.4.0-77.86~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-5.4.0-77-lowlatency', 'pkgver': '5.4.0-77.86~18.04.1'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws', 'pkgver': '5.4.0.1051.33'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-edge', 'pkgver': '5.4.0.1051.33'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure', 'pkgver': '5.4.0.1051.30'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '5.4.0.1051.30'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp', 'pkgver': '5.4.0.1046.33'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-edge', 'pkgver': '5.4.0.1046.33'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1046.48~18.04.12'},
    {'osver': '18.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1018.19~18.04.19'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle', 'pkgver': '5.4.0.1048.52~18.04.30'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-edge', 'pkgver': '5.4.0.1048.52~18.04.30'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1038.40'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1038.40'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon-hwe-18.04-edge', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.77.86~18.04.69'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1018-gkeop', 'pkgver': '5.4.0-1018.19'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1038-raspi', 'pkgver': '5.4.0-1038.41'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1046-gcp', 'pkgver': '5.4.0-1046.49'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1046-gke', 'pkgver': '5.4.0-1046.48'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1048-oracle', 'pkgver': '5.4.0-1048.52'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1051-aws', 'pkgver': '5.4.0-1051.53'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-1051-azure', 'pkgver': '5.4.0-1051.53'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-77-generic', 'pkgver': '5.4.0-77.86'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-77-generic-lpae', 'pkgver': '5.4.0-77.86'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-77-lowlatency', 'pkgver': '5.4.0-77.86'},
    {'osver': '20.04', 'pkgname': 'linux-image-aws-lts-20.04', 'pkgver': '5.4.0.1051.53'},
    {'osver': '20.04', 'pkgname': 'linux-image-azure-lts-20.04', 'pkgver': '5.4.0.1051.49'},
    {'osver': '20.04', 'pkgname': 'linux-image-gcp-lts-20.04', 'pkgver': '5.4.0.1046.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-gke', 'pkgver': '5.4.0.1046.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-gke-5.4', 'pkgver': '5.4.0.1046.55'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop', 'pkgver': '5.4.0.1018.21'},
    {'osver': '20.04', 'pkgname': 'linux-image-gkeop-5.4', 'pkgver': '5.4.0.1018.21'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-oracle-lts-20.04', 'pkgver': '5.4.0.1048.48'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi', 'pkgver': '5.4.0.1038.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04', 'pkgver': '5.4.0.1038.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi-hwe-18.04-edge', 'pkgver': '5.4.0.1038.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '5.4.0.1038.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04', 'pkgver': '5.4.0.1038.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-raspi2-hwe-18.04-edge', 'pkgver': '5.4.0.1038.73'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.77.80'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.77.80'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-image-5.4.0-1018-gkeop / linux-image-5.4.0-1038-raspi / etc');
}
