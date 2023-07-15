#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5018-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(151920);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-26139",
    "CVE-2020-26147",
    "CVE-2020-26558",
    "CVE-2021-0129",
    "CVE-2021-23134",
    "CVE-2021-31829",
    "CVE-2021-32399",
    "CVE-2021-33034",
    "CVE-2021-33200",
    "CVE-2021-33909"
  );
  script_xref(name:"USN", value:"5018-1");
  script_xref(name:"IAVA", value:"2021-A-0350");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : Linux kernel vulnerabilities (USN-5018-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by multiple vulnerabilities as
referenced in the USN-5018-1 advisory.

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that received fragments be cleared from memory after (re)connecting to a
    network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP,
    CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or exfiltrate user data.
    (CVE-2020-24586)

  - The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent
    Privacy (WEP) doesn't require that all fragments of a frame are encrypted under the same key. An adversary
    can abuse this to decrypt selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP encryption key is periodically renewed. (CVE-2020-24587)

  - An issue was discovered in the kernel in NetBSD 7.1. An Access Point (AP) forwards EAPOL frames to other
    clients even though the sender has not yet successfully authenticated to the AP. This might be abused in
    projected Wi-Fi networks to launch denial-of-service attacks against connected clients and makes it easier
    to exploit other vulnerabilities in connected clients. (CVE-2020-26139)

  - An issue was discovered in the Linux kernel 5.8.9. The WEP, WPA, WPA2, and WPA3 implementations reassemble
    fragments even though some of them were sent in plaintext. This vulnerability can be abused to inject
    packets and/or exfiltrate selected fragments when another device sends fragmented frames and the WEP,
    CCMP, or GCMP data-confidentiality protocol is used. (CVE-2020-26147)

  - Bluetooth LE and BR/EDR secure pairing in Bluetooth Core Specification 2.1 through 5.2 may permit a nearby
    man-in-the-middle attacker to identify the Passkey used during pairing (in the Passkey authentication
    procedure) by reflection of the public key and the authentication evidence of the initiating device,
    potentially permitting this attacker to complete authenticated pairing with the responding device using
    the correct Passkey for the pairing session. The attack methodology determines the Passkey value one bit
    at a time. (CVE-2020-26558)

  - Improper access control in BlueZ may allow an authenticated user to potentially enable information
    disclosure via adjacent access. (CVE-2021-0129)

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

  - fs/seq_file.c in the Linux kernel 3.16 through 5.13.x before 5.13.4 does not properly restrict seq buffer
    allocations, leading to an integer overflow, an Out-of-bounds Write, and escalation to root by an
    unprivileged user, aka CID-8cae8cd89f05. (CVE-2021-33909)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5018-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33200");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:block-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:block-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:crypto-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:crypto-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dasd-extra-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dasd-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fat-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fat-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fb-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:firewire-core-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:floppy-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fs-core-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fs-core-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fs-secondary-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fs-secondary-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:input-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:input-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ipmi-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ipmi-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:irda-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:irda-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kernel-image-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kernel-image-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:kernel-signed-image-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-cloud-tools-4.15.0-1109");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-headers-4.15.0-1109");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe-cloud-tools-4.15.0-1109");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-hwe-tools-4.15.0-1109");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-aws-tools-4.15.0-1109");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-cloud-tools-4.15.0-1121");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-headers-4.15.0-1121");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-4.15-tools-4.15.0-1121");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-cloud-tools-4.15.0-1121");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-headers-4.15.0-1121");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-azure-tools-4.15.0-1121");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1078-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1092-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1097-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1106-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1109-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1109-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-1121-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-151-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-151-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-4.15.0-151-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1109-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-1121-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-151");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-151-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-4.15.0-151-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-4.15-headers-4.15.0-1106");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-4.15-tools-4.15.0-1106");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-headers-4.15.0-1106");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gcp-tools-4.15.0-1106");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1078-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1092-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1097-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1106-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1109-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1109-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-1121-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-151");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-151-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-151-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-4.15.0-151-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-cloud-tools-4.15.0-151");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-tools-4.15.0-151");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-hwe-udebs-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1078-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1092-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1097-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1106-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1109-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1109-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1121-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-151-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-151-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-151-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1078-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1106-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-1121-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-151-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-4.15.0-151-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-headers-4.15.0-1097");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-kvm-tools-4.15.0-1097");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1078-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1092-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1097-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1106-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1109-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1109-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-1121-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-151-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-151-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-4.15.0-151-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1078-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1106-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1109-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-1121-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-4.15.0-151-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-headers-4.15.0-1078");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oracle-tools-4.15.0-1078");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-headers-4.15.0-1092");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-raspi2-tools-4.15.0-1092");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-image-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-signed-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-headers-4.15.0-1109");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-snapdragon-tools-4.15.0-1109");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-4.15.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1078-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1092-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1097-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1106-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1109-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1109-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-1121-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-151");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-151-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-151-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-4.15.0-151-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-hwe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-aws-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-azure-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gcp-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oracle-lts-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-snapdragon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-udebs-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-udebs-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-16.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-16.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:md-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:md-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:message-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mouse-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:mouse-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multipath-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:multipath-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nfs-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nfs-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-pcmcia-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-shared-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-shared-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-usb-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:nic-usb-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:parport-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:parport-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pata-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pcmcia-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pcmcia-storage-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plip-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:plip-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ppp-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ppp-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sata-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:sata-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:scsi-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:scsi-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:serial-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:storage-core-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:storage-core-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:usb-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:usb-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:virtio-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlan-modules-4.15.0-151-generic-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:vlan-modules-4.15.0-151-generic-lpae-di");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (! preg(pattern:"^(16\.04|18\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  cve_list = make_list('CVE-2020-24586', 'CVE-2020-24587', 'CVE-2020-26139', 'CVE-2020-26147', 'CVE-2020-26558', 'CVE-2021-0129', 'CVE-2021-23134', 'CVE-2021-31829', 'CVE-2021-32399', 'CVE-2021-33034', 'CVE-2021-33200', 'CVE-2021-33909');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5018-1');
  }
  else
  {
    _ubuntu_report = ksplice_reporting_text();
  }
}

pkgs = [
    {'osver': '16.04', 'pkgname': 'block-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'crypto-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'dasd-extra-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'dasd-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'fat-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'fb-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'firewire-core-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'floppy-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'fs-core-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'fs-secondary-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'input-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'ipmi-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'irda-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'kernel-image-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'kernel-signed-image-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-edge', 'pkgver': '4.15.0.1109.100'},
    {'osver': '16.04', 'pkgname': 'linux-aws-headers-4.15.0-1109', 'pkgver': '4.15.0-1109.116~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe', 'pkgver': '4.15.0.1109.100'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe-cloud-tools-4.15.0-1109', 'pkgver': '4.15.0-1109.116~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-aws-hwe-tools-4.15.0-1109', 'pkgver': '4.15.0-1109.116~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-azure-cloud-tools-4.15.0-1121', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure-edge', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-azure-headers-4.15.0-1121', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-azure-tools-4.15.0-1121', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-151-generic', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-buildinfo-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-151-generic', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-azure', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-azure-edge', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-gcp', 'pkgver': '4.15.0.1106.107'},
    {'osver': '16.04', 'pkgname': 'linux-gcp-headers-4.15.0-1106', 'pkgver': '4.15.0-1106.120~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-gcp-tools-4.15.0-1106', 'pkgver': '4.15.0-1106.120~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-gke', 'pkgver': '4.15.0.1106.107'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-151', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-151-generic', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-headers-aws-hwe', 'pkgver': '4.15.0.1109.100'},
    {'osver': '16.04', 'pkgname': 'linux-headers-azure', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-headers-azure-edge', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-headers-gcp', 'pkgver': '4.15.0.1106.107'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-headers-gke', 'pkgver': '4.15.0.1106.107'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oem', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-headers-oracle', 'pkgver': '4.15.0.1078.66'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-cloud-tools-4.15.0-151', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-tools-4.15.0-151', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-hwe-udebs-generic', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-151-generic', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-aws-hwe', 'pkgver': '4.15.0.1109.100'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-image-azure-edge', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-image-gcp', 'pkgver': '4.15.0.1106.107'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-image-gke', 'pkgver': '4.15.0.1106.107'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-image-oem', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-image-oracle', 'pkgver': '4.15.0.1078.66'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-151-generic', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-unsigned-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-151-generic', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-4.15.0-151-generic', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-aws-hwe', 'pkgver': '4.15.0.1109.100'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-azure', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-azure-edge', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-gcp', 'pkgver': '4.15.0.1106.107'},
    {'osver': '16.04', 'pkgname': 'linux-modules-extra-gke', 'pkgver': '4.15.0.1106.107'},
    {'osver': '16.04', 'pkgname': 'linux-oem', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-oracle', 'pkgver': '4.15.0.1078.66'},
    {'osver': '16.04', 'pkgname': 'linux-oracle-headers-4.15.0-1078', 'pkgver': '4.15.0-1078.86~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-oracle-tools-4.15.0-1078', 'pkgver': '4.15.0-1078.86~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-signed-azure', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-signed-azure-edge', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-azure', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-azure-edge', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oem', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-signed-image-oracle', 'pkgver': '4.15.0.1078.66'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oem', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-signed-oracle', 'pkgver': '4.15.0.1078.66'},
    {'osver': '16.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-151-generic', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'linux-tools-aws-hwe', 'pkgver': '4.15.0.1109.100'},
    {'osver': '16.04', 'pkgname': 'linux-tools-azure', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-tools-azure-edge', 'pkgver': '4.15.0.1121.112'},
    {'osver': '16.04', 'pkgname': 'linux-tools-gcp', 'pkgver': '4.15.0.1106.107'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-tools-gke', 'pkgver': '4.15.0.1106.107'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oem', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-tools-oracle', 'pkgver': '4.15.0.1078.66'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.146'},
    {'osver': '16.04', 'pkgname': 'md-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'message-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'mouse-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'multipath-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'nfs-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'nic-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'nic-pcmcia-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'nic-shared-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'nic-usb-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'parport-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'pata-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'pcmcia-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'pcmcia-storage-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'plip-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'ppp-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'sata-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'scsi-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'serial-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'storage-core-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'usb-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'virtio-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '16.04', 'pkgname': 'vlan-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157~16.04.1'},
    {'osver': '18.04', 'pkgname': 'block-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'block-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'crypto-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'crypto-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'dasd-extra-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'dasd-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'fat-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'fat-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'fb-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'firewire-core-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'floppy-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'fs-core-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'fs-core-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'fs-secondary-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'fs-secondary-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'input-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'input-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'ipmi-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'ipmi-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'irda-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'irda-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'kernel-image-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'kernel-image-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'kernel-signed-image-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-aws-cloud-tools-4.15.0-1109', 'pkgver': '4.15.0-1109.116'},
    {'osver': '18.04', 'pkgname': 'linux-aws-headers-4.15.0-1109', 'pkgver': '4.15.0-1109.116'},
    {'osver': '18.04', 'pkgname': 'linux-aws-lts-18.04', 'pkgver': '4.15.0.1109.112'},
    {'osver': '18.04', 'pkgname': 'linux-aws-tools-4.15.0-1109', 'pkgver': '4.15.0-1109.116'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-cloud-tools-4.15.0-1121', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-headers-4.15.0-1121', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-azure-4.15-tools-4.15.0-1121', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-azure-lts-18.04', 'pkgver': '4.15.0.1121.94'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1092-raspi2', 'pkgver': '4.15.0-1092.98'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1097-kvm', 'pkgver': '4.15.0-1097.99'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1109-snapdragon', 'pkgver': '4.15.0-1109.118'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-151-generic', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-151-generic-lpae', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-buildinfo-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-151', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-151-generic', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-azure-lts-18.04', 'pkgver': '4.15.0.1121.94'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-crashdump', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-4.15-headers-4.15.0-1106', 'pkgver': '4.15.0-1106.120'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-4.15-tools-4.15.0-1106', 'pkgver': '4.15.0-1106.120'},
    {'osver': '18.04', 'pkgname': 'linux-gcp-lts-18.04', 'pkgver': '4.15.0.1106.125'},
    {'osver': '18.04', 'pkgname': 'linux-generic', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1092-raspi2', 'pkgver': '4.15.0-1092.98'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1097-kvm', 'pkgver': '4.15.0-1097.99'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1109-snapdragon', 'pkgver': '4.15.0-1109.118'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-151', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-151-generic', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-151-generic-lpae', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-headers-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-headers-aws-lts-18.04', 'pkgver': '4.15.0.1109.112'},
    {'osver': '18.04', 'pkgname': 'linux-headers-azure-lts-18.04', 'pkgver': '4.15.0.1121.94'},
    {'osver': '18.04', 'pkgname': 'linux-headers-gcp-lts-18.04', 'pkgver': '4.15.0.1106.125'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-kvm', 'pkgver': '4.15.0.1097.93'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-oracle-lts-18.04', 'pkgver': '4.15.0.1078.88'},
    {'osver': '18.04', 'pkgname': 'linux-headers-raspi2', 'pkgver': '4.15.0.1092.90'},
    {'osver': '18.04', 'pkgname': 'linux-headers-snapdragon', 'pkgver': '4.15.0.1109.112'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-headers-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1092-raspi2', 'pkgver': '4.15.0-1092.98'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1097-kvm', 'pkgver': '4.15.0-1097.99'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1109-snapdragon', 'pkgver': '4.15.0-1109.118'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-151-generic', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-151-generic-lpae', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-image-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-image-aws-lts-18.04', 'pkgver': '4.15.0.1109.112'},
    {'osver': '18.04', 'pkgname': 'linux-image-azure-lts-18.04', 'pkgver': '4.15.0.1121.94'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-extra-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-gcp-lts-18.04', 'pkgver': '4.15.0.1106.125'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-kvm', 'pkgver': '4.15.0.1097.93'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-oracle-lts-18.04', 'pkgver': '4.15.0.1078.88'},
    {'osver': '18.04', 'pkgname': 'linux-image-raspi2', 'pkgver': '4.15.0.1092.90'},
    {'osver': '18.04', 'pkgname': 'linux-image-snapdragon', 'pkgver': '4.15.0.1109.112'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-151-generic', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-image-unsigned-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-image-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-kvm', 'pkgver': '4.15.0.1097.93'},
    {'osver': '18.04', 'pkgname': 'linux-kvm-headers-4.15.0-1097', 'pkgver': '4.15.0-1097.99'},
    {'osver': '18.04', 'pkgname': 'linux-kvm-tools-4.15.0-1097', 'pkgver': '4.15.0-1097.99'},
    {'osver': '18.04', 'pkgname': 'linux-libc-dev', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1092-raspi2', 'pkgver': '4.15.0-1092.98'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1097-kvm', 'pkgver': '4.15.0-1097.99'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1109-snapdragon', 'pkgver': '4.15.0-1109.118'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-151-generic', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-151-generic-lpae', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-modules-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-4.15.0-151-generic', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-aws-lts-18.04', 'pkgver': '4.15.0.1109.112'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-azure-lts-18.04', 'pkgver': '4.15.0.1121.94'},
    {'osver': '18.04', 'pkgname': 'linux-modules-extra-gcp-lts-18.04', 'pkgver': '4.15.0.1106.125'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-headers-4.15.0-1078', 'pkgver': '4.15.0-1078.86'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-lts-18.04', 'pkgver': '4.15.0.1078.88'},
    {'osver': '18.04', 'pkgname': 'linux-oracle-tools-4.15.0-1078', 'pkgver': '4.15.0-1078.86'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2', 'pkgver': '4.15.0.1092.90'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2-headers-4.15.0-1092', 'pkgver': '4.15.0-1092.98'},
    {'osver': '18.04', 'pkgname': 'linux-raspi2-tools-4.15.0-1092', 'pkgver': '4.15.0-1092.98'},
    {'osver': '18.04', 'pkgname': 'linux-signed-azure-lts-18.04', 'pkgver': '4.15.0.1121.94'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-azure-lts-18.04', 'pkgver': '4.15.0.1121.94'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-image-oracle-lts-18.04', 'pkgver': '4.15.0.1078.88'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-signed-oracle-lts-18.04', 'pkgver': '4.15.0.1078.88'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon', 'pkgver': '4.15.0.1109.112'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-headers-4.15.0-1109', 'pkgver': '4.15.0-1109.118'},
    {'osver': '18.04', 'pkgname': 'linux-snapdragon-tools-4.15.0-1109', 'pkgver': '4.15.0-1109.118'},
    {'osver': '18.04', 'pkgname': 'linux-source', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-source-4.15.0', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1078-oracle', 'pkgver': '4.15.0-1078.86'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1092-raspi2', 'pkgver': '4.15.0-1092.98'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1097-kvm', 'pkgver': '4.15.0-1097.99'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1106-gcp', 'pkgver': '4.15.0-1106.120'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1109-aws', 'pkgver': '4.15.0-1109.116'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1109-snapdragon', 'pkgver': '4.15.0-1109.118'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-1121-azure', 'pkgver': '4.15.0-1121.134'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-151', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-151-generic', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-151-generic-lpae', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-tools-4.15.0-151-lowlatency', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-tools-aws-lts-18.04', 'pkgver': '4.15.0.1109.112'},
    {'osver': '18.04', 'pkgname': 'linux-tools-azure-lts-18.04', 'pkgver': '4.15.0.1121.94'},
    {'osver': '18.04', 'pkgname': 'linux-tools-common', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-tools-gcp-lts-18.04', 'pkgver': '4.15.0.1106.125'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-generic-lpae-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-host', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-tools-kvm', 'pkgver': '4.15.0.1097.93'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-lowlatency-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-oracle-lts-18.04', 'pkgver': '4.15.0.1078.88'},
    {'osver': '18.04', 'pkgname': 'linux-tools-raspi2', 'pkgver': '4.15.0.1092.90'},
    {'osver': '18.04', 'pkgname': 'linux-tools-snapdragon', 'pkgver': '4.15.0.1109.112'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-tools-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-udebs-generic', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-udebs-generic-lpae', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'linux-virtual', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'linux-virtual-hwe-16.04-edge', 'pkgver': '4.15.0.151.139'},
    {'osver': '18.04', 'pkgname': 'md-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'md-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'message-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'mouse-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'mouse-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'multipath-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'multipath-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'nfs-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'nfs-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'nic-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'nic-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'nic-pcmcia-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'nic-shared-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'nic-shared-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'nic-usb-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'nic-usb-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'parport-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'parport-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'pata-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'pcmcia-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'pcmcia-storage-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'plip-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'plip-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'ppp-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'ppp-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'sata-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'sata-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'scsi-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'scsi-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'serial-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'storage-core-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'storage-core-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'usb-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'usb-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'virtio-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'vlan-modules-4.15.0-151-generic-di', 'pkgver': '4.15.0-151.157'},
    {'osver': '18.04', 'pkgname': 'vlan-modules-4.15.0-151-generic-lpae-di', 'pkgver': '4.15.0-151.157'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'block-modules-4.15.0-151-generic-di / etc');
}
