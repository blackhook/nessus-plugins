#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5127. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(160469);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2021-4197",
    "CVE-2022-0168",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-1158",
    "CVE-2022-1195",
    "CVE-2022-1198",
    "CVE-2022-1199",
    "CVE-2022-1204",
    "CVE-2022-1205",
    "CVE-2022-1353",
    "CVE-2022-1516",
    "CVE-2022-26490",
    "CVE-2022-27666",
    "CVE-2022-28356",
    "CVE-2022-28388",
    "CVE-2022-28389",
    "CVE-2022-28390",
    "CVE-2022-29582"
  );

  script_name(english:"Debian DSA-5127-1 : linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5127 advisory.

  - An unprivileged write to the file handler flaw in the Linux kernel's control groups and namespaces
    subsystem was found in the way users have access to some less privileged process that are controlled by
    cgroups and have higher privileged parent process. It is actually both for cgroup2 and cgroup1 versions of
    control groups. A local user could use this flaw to crash the system or escalate their privileges on the
    system. (CVE-2021-4197)

  - A use-after-free flaw was found in the Linux kernel's sound subsystem in the way a user triggers
    concurrent calls of PCM hw_params. The hw_free ioctls or similar race condition happens inside ALSA PCM
    for other ioctls. This flaw allows a local user to crash or potentially escalate their privileges on the
    system. (CVE-2022-1048)

  - A use-after-free vulnerability was found in the Linux kernel in drivers/net/hamradio. This flaw allows a
    local attacker with a user privilege to cause a denial of service (DOS) when the mkiss or sixpack device
    is detached and reclaim resources early. (CVE-2022-1195)

  - A vulnerability was found in the pfkey_register function in net/key/af_key.c in the Linux kernel. This
    flaw allows a local, unprivileged user to gain access to kernel memory, leading to a system crash or a
    leak of internal kernel information. (CVE-2022-1353)

  - st21nfca_connectivity_event_received in drivers/nfc/st21nfca/se.c in the Linux kernel through 5.16.12 has
    EVT_TRANSACTION buffer overflows because of untrusted length parameters. (CVE-2022-26490)

  - A heap buffer overflow flaw was found in IPsec ESP transformation code in net/ipv4/esp4.c and
    net/ipv6/esp6.c. This flaw allows a local attacker with a normal user privilege to overwrite kernel heap
    objects and may cause a local privilege escalation threat. (CVE-2022-27666)

  - In the Linux kernel before 5.17.1, a refcount leak bug was found in net/llc/af_llc.c. (CVE-2022-28356)

  - usb_8dev_start_xmit in drivers/net/can/usb/usb_8dev.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28388)

  - mcba_usb_start_xmit in drivers/net/can/usb/mcba_usb.c in the Linux kernel through 5.17.1 has a double
    free. (CVE-2022-28389)

  - ems_usb_start_xmit in drivers/net/can/usb/ems_usb.c in the Linux kernel through 5.17.1 has a double free.
    (CVE-2022-28390)

  - In the Linux kernel before 5.17.3, fs/io_uring.c has a use-after-free due to a race condition in io_uring
    timeouts. This can be triggered by a local user who has no access to any user namespace; however, the race
    condition perhaps can only be exploited infrequently. (CVE-2022-29582)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5127");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4197");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0168");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1158");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1195");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1198");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1199");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1204");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1205");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1353");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1516");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26490");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27666");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28356");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28388");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28389");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28390");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29582");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.

For the stable distribution (bullseye), these problems have been fixed in version 5.10.113-1.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4197");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28390");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:affs-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ata-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:btrfs-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cdrom-core-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crc-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-dm-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:crypto-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-extra-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dasd-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:efi-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:event-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ext4-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:f2fs-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fancontrol-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fat-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fb-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firewire-core-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuse-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hypervisor-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:i2c-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:input-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ipv6-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isofs-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jffs2-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jfs-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-image-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:leds-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-10-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-armmlpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-10-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmlpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-armmdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-armmlpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-armmlpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-rt-armmdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-10-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmlpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmlpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:loomodules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:md-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:minix-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-core-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mmc-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mouse-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-core-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mtd-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:multipath-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nbd-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nfs-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-shared-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-usb-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nic-wireless-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pata-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppmodules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rtc-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sata-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-core-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:scsi-nic-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:serial-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sound-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakumodules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:speakumodules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squashfs-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:udf-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uinput-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-serial-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-10-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-10-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-13-armmdi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-13-marvell-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usb-storage-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-10-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-10-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-10-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-10-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-10-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-10-s390x-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-13-4kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-13-5kc-malta-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-13-loongson-3-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-13-octeon-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-13-powerpc64le-di");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xfs-modules-5.10.0-13-s390x-di");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
var release = chomp(release);
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'affs-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ata-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'bpftool', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'btrfs-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'cdrom-core-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crc-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-dm-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'crypto-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'dasd-extra-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'dasd-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'efi-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'event-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ext4-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'f2fs-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fancontrol-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fat-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fb-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'firewire-core-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'fuse-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'hyperv-daemons', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'hypervisor-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'i2c-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'input-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ipv6-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'isofs-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jffs2-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'jfs-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'kernel-image-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'leds-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'libcpupower-dev', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'libcpupower1', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-arm', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-s390', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-compiler-gcc-10-x86', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-cpupower', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-doc', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-4kc-malta', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-4kc-malta', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-5kc-malta', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-686', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-686-pae', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-amd64', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-arm64', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-armmp', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-armmp-lpae', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-cloud-amd64', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-cloud-arm64', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-common', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-common-rt', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-loongson-3', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-marvell', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-octeon', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-powerpc64le', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-rpi', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-rt-686-pae', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-rt-amd64', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-rt-arm64', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-rt-armmp', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5.10.0-10-s390x', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-5kc-malta', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-armmp-lpae', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-loongson-3', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-marvell', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-octeon', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-powerpc64le', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rpi', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-rt-armmp', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-headers-s390x', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-4kc-malta-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-4kc-malta', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-4kc-malta-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-5kc-malta', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-5kc-malta-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-686-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-686-pae-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-686-pae-unsigned', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-686-unsigned', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-amd64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-amd64-unsigned', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-arm64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-arm64-unsigned', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-armmp', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-armmp-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-armmp-lpae', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-armmp-lpae-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-cloud-amd64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-cloud-amd64-unsigned', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-cloud-arm64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-cloud-arm64-unsigned', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-loongson-3', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-loongson-3-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-marvell', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-marvell-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-octeon', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-octeon-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-powerpc64le', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-powerpc64le-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-rpi', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-rpi-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-rt-686-pae-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-rt-686-pae-unsigned', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-rt-amd64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-rt-amd64-unsigned', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-rt-arm64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-rt-arm64-unsigned', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-rt-armmp', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-rt-armmp-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-s390x', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5.10.0-10-s390x-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-5kc-malta-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-686-pae-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-armmp-lpae-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-amd64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-cloud-arm64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-loongson-3-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-marvell-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-octeon-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-powerpc64le-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-rpi-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-686-pae-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-amd64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-arm64-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-rt-armmp-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-image-s390x-dbg', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-libc-dev', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-perf', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-source', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'linux-support-5.10.0-10', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'loop-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'md-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'minix-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-core-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mmc-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mouse-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-core-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'mtd-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'multipath-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nbd-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nfs-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-shared-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-usb-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'nic-wireless-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'pata-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'ppp-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'rtc-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sata-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-core-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'scsi-nic-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'serial-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'sound-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'speakup-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'squashfs-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'udf-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'uinput-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-serial-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-10-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-10-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-13-armmp-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-13-marvell-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usb-storage-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'usbip', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-10-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-10-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-10-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-10-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-10-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-10-s390x-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-13-4kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-13-5kc-malta-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-13-loongson-3-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-13-octeon-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-13-powerpc64le-di', 'reference': '5.10.113-1'},
    {'release': '11.0', 'prefix': 'xfs-modules-5.10.0-13-s390x-di', 'reference': '5.10.113-1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'affs-modules-5.10.0-10-4kc-malta-di / etc');
}
