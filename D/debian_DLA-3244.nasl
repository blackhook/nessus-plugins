#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3244. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(169293);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/24");

  script_cve_id(
    "CVE-2021-3759",
    "CVE-2022-3169",
    "CVE-2022-3435",
    "CVE-2022-3521",
    "CVE-2022-3524",
    "CVE-2022-3564",
    "CVE-2022-3565",
    "CVE-2022-3594",
    "CVE-2022-3628",
    "CVE-2022-3640",
    "CVE-2022-3643",
    "CVE-2022-4139",
    "CVE-2022-4378",
    "CVE-2022-4751",
    "CVE-2022-41849",
    "CVE-2022-41850",
    "CVE-2022-42328",
    "CVE-2022-42329",
    "CVE-2022-42895",
    "CVE-2022-42896",
    "CVE-2022-47518",
    "CVE-2022-47519",
    "CVE-2022-47520",
    "CVE-2022-47521"
  );

  script_name(english:"Debian DLA-3244-1 : linux-5.10 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3244 advisory.

  - A memory overflow vulnerability was found in the Linux kernel's ipc functionality of the memcg subsystem,
    in the way a user calls the semget function multiple times, creating semaphores. This flaw allows a local
    user to starve the resources, causing a denial of service. The highest threat from this vulnerability is
    to system availability. (CVE-2021-3759)

  - A flaw was found in the Linux kernel. A denial of service flaw may occur if there is a consecutive request
    of the NVME_IOCTL_RESET and the NVME_IOCTL_SUBSYS_RESET through the device file of the driver, resulting
    in a PCIe link disconnect. (CVE-2022-3169)

  - A vulnerability classified as problematic has been found in Linux Kernel. This affects the function
    fib_nh_match of the file net/ipv4/fib_semantics.c of the component IPv4 Handler. The manipulation leads to
    out-of-bounds read. It is possible to initiate the attack remotely. It is recommended to apply a patch to
    fix this issue. The identifier VDB-210357 was assigned to this vulnerability. (CVE-2022-3435)

  - A vulnerability has been found in Linux Kernel and classified as problematic. This vulnerability affects
    the function kcm_tx_work of the file net/kcm/kcmsock.c of the component kcm. The manipulation leads to
    race condition. It is recommended to apply a patch to fix this issue. VDB-211018 is the identifier
    assigned to this vulnerability. (CVE-2022-3521)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function ipv6_renew_options of the component IPv6 Handler. The manipulation leads to
    memory leak. The attack can be launched remotely. It is recommended to apply a patch to fix this issue.
    The identifier VDB-211021 was assigned to this vulnerability. (CVE-2022-3524)

  - A vulnerability classified as critical was found in Linux Kernel. Affected by this vulnerability is the
    function l2cap_reassemble_sdu of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The associated
    identifier of this vulnerability is VDB-211087. (CVE-2022-3564)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function del_timer of the file drivers/isdn/mISDN/l1oip_core.c of the component Bluetooth. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    of this vulnerability is VDB-211088. (CVE-2022-3565)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function intr_callback of the file drivers/net/usb/r8152.c of the component BPF. The
    manipulation leads to logging of excessive data. The attack can be launched remotely. It is recommended to
    apply a patch to fix this issue. The associated identifier of this vulnerability is VDB-211363.
    (CVE-2022-3594)

  - A vulnerability, which was classified as critical, was found in Linux Kernel. Affected is the function
    l2cap_conn_del of the file net/bluetooth/l2cap_core.c of the component Bluetooth. The manipulation leads
    to use after free. It is recommended to apply a patch to fix this issue. The identifier of this
    vulnerability is VDB-211944. (CVE-2022-3640)

  - Guests can trigger NIC interface reset/abort/crash via netback It is possible for a guest to trigger a NIC
    interface reset/abort/crash in a Linux based network backend by sending certain kinds of packets. It
    appears to be an (unwritten?) assumption in the rest of the Linux network stack that packet protocol
    headers are all contained within the linear section of the SKB and some NICs behave badly if this is not
    the case. This has been reported to occur with Cisco (enic) and Broadcom NetXtrem II BCM5780 (bnx2x)
    though it may be an issue with other NICs/drivers as well. In case the frontend is sending requests with
    split headers, netback will forward those violating above mentioned assumption to the networking core,
    resulting in said misbehavior. (CVE-2022-3643)

  - drivers/video/fbdev/smscufx.c in the Linux kernel through 5.19.12 has a race condition and resultant use-
    after-free if a physically proximate attacker removes a USB device while calling open(), aka a race
    condition between ufx_ops_open and ufx_usb_disconnect. (CVE-2022-41849)

  - roccat_report_event in drivers/hid/hid-roccat.c in the Linux kernel through 5.19.12 has a race condition
    and resultant use-after-free in certain situations where a report is received while copying a
    report->value is in progress. (CVE-2022-41850)

  - Guests can trigger deadlock in Linux netback driver T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] The patch for XSA-392 introduced
    another issue which might result in a deadlock when trying to free the SKB of a packet dropped due to the
    XSA-392 handling (CVE-2022-42328). Additionally when dropping packages for other reasons the same deadlock
    could occur in case of netpoll being active for the interface the xen-netback driver is connected to
    (CVE-2022-42329). (CVE-2022-42328, CVE-2022-42329)

  - There is an infoleak vulnerability in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_parse_conf_req
    function which can be used to leak kernel pointers remotely. We recommend upgrading past commit
    https://github.com/torvalds/linux/commit/b1a2cd50c0357f243b7435a732b4e62ba3157a2e
    https://www.google.com/url (CVE-2022-42895)

  - There are use-after-free vulnerabilities in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_connect
    and l2cap_le_connect_req functions which may allow code execution and leaking kernel memory (respectively)
    remotely via Bluetooth. A remote attacker could execute code leaking kernel memory via Bluetooth if within
    proximity of the victim. We recommend upgrading past commit https://www.google.com/url
    https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4
    https://www.google.com/url (CVE-2022-42896)

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

  - Incorrect GPU TLB flush can lead to random memory access [fedora-all] (CVE-2022-4139)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1022806");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux-5.10");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3244");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3759");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3169");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3435");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3521");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3524");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3564");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3565");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3628");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3640");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3643");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4139");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41849");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41850");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42328");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42329");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42895");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-42896");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4378");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4751");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47518");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47519");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47520");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47521");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux-5.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-5.10 packages.

For Debian 10 buster, these problems have been fixed in version 5.10.158-2~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.20");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp-lpae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-rt-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-686', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-686-pae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-amd64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-arm64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-armmp-lpae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-cloud-amd64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-cloud-arm64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-common', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-common-rt', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-686-pae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-amd64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-arm64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-686', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-686-pae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-amd64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-arm64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-armmp-lpae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-cloud-amd64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-cloud-arm64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-common', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-common-rt', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-686-pae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-amd64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-arm64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-686', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-686-pae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-amd64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-arm64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-armmp-lpae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-cloud-amd64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-cloud-arm64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-common', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-common-rt', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-686-pae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-amd64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-arm64', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-pae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-signed-template', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-signed-template', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-i386-signed-template', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-686-pae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-pae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-pae-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-amd64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-arm64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-lpae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-armmp-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-pae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-pae-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-amd64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-arm64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-lpae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-armmp-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-pae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-pae-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-amd64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-arm64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-lpae', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-lpae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-amd64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-arm64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-686-pae-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-686-pae-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-amd64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-amd64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-arm64-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-arm64-unsigned', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-armmp', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-armmp-dbg', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.17', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.19', 'reference': '5.10.158-2~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.20', 'reference': '5.10.158-2~deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-config-5.10 / linux-doc-5.10 / linux-headers-5.10-armmp / etc');
}
