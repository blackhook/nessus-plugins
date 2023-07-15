#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4843. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(146052);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id("CVE-2020-27815", "CVE-2020-27825", "CVE-2020-27830", "CVE-2020-28374", "CVE-2020-29568", "CVE-2020-29569", "CVE-2020-29660", "CVE-2020-29661", "CVE-2020-36158", "CVE-2021-20177", "CVE-2021-3347");
  script_xref(name:"DSA", value:"4843");

  script_name(english:"Debian DSA-4843-1 : linux - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

  - CVE-2020-27815
    A flaw was reported in the JFS filesystem code allowing
    a local attacker with the ability to set extended
    attributes to cause a denial of service.

  - CVE-2020-27825
    Adam 'pi3' Zabrocki reported a use-after-free flaw in
    the ftrace ring buffer resizing logic due to a race
    condition, which could result in denial of service or
    information leak.

  - CVE-2020-27830
    Shisong Qin reported a NULL pointer dereference flaw in
    the Speakup screen reader core driver.

  - CVE-2020-28374
    David Disseldorp discovered that the LIO SCSI target
    implementation performed insufficient checking in
    certain XCOPY requests. An attacker with access to a LUN
    and knowledge of Unit Serial Number assignments can take
    advantage of this flaw to read and write to any LIO
    backstore, regardless of the SCSI transport settings.

  - CVE-2020-29568 (XSA-349)
    Michael Kurth and Pawel Wieczorkiewicz reported that
    frontends can trigger OOM in backends by updating a
    watched path.

  - CVE-2020-29569 (XSA-350)
    Olivier Benjamin and Pawel Wieczorkiewicz reported a
    use-after-free flaw which can be triggered by a block
    frontend in Linux blkback. A misbehaving guest can
    trigger a dom0 crash by continuously connecting /
    disconnecting a block frontend.

  - CVE-2020-29660
    Jann Horn reported a locking inconsistency issue in the
    tty subsystem which may allow a local attacker to mount
    a read-after-free attack against TIOCGSID.

  - CVE-2020-29661
    Jann Horn reported a locking issue in the tty subsystem
    which can result in a use-after-free. A local attacker
    can take advantage of this flaw for memory corruption or
    privilege escalation.

  - CVE-2020-36158
    A buffer overflow flaw was discovered in the mwifiex
    WiFi driver which could result in denial of service or
    the execution of arbitrary code via a long SSID value.

  - CVE-2021-3347
    It was discovered that PI futexes have a kernel stack
    use-after-free during fault handling. An unprivileged
    user could use this flaw to crash the kernel (resulting
    in denial of service) or for privilege escalation.

  - CVE-2021-20177
    A flaw was discovered in the Linux implementation of
    string matching within a packet. A privileged user (with
    root or CAP_NET_ADMIN) can take advantage of this flaw
    to cause a kernel panic when inserting iptables rules."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=970736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=972345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=977048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=977615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-27815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-27825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-27830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-28374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-29568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-29569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-29660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-29661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-36158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-3347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-20177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/linux"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4843"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the linux packages.

For the stable distribution (buster), these problems have been fixed
in version 4.19.171-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3347");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"affs-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ata-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"btrfs-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"cdrom-core-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"compress-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crc-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-dm-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"crypto-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"dasd-extra-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"dasd-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"efi-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"event-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ext4-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fancontrol-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fat-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fb-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"firewire-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"firewire-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"fuse-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"hfs-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"hyperv-daemons", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"hypervisor-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"i2c-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"input-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ipv6-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"isofs-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"jffs2-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"jfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"kernel-image-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"leds-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"leds-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"libbpf-dev", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"libbpf4.19", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"libcpupower-dev", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"libcpupower1", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"liblockdep-dev", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"liblockdep4.19", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-compiler-gcc-8-arm", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-compiler-gcc-8-s390", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-compiler-gcc-8-x86", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-config-4.19", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-cpupower", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-doc-4.19", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-4kc-malta", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-5kc-malta", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-686", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-686-pae", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-amd64", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-arm64", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-armel", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-armhf", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-i386", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-mips", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-mips64el", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-mipsel", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-ppc64el", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-all-s390x", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-amd64", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-arm64", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-armmp", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-armmp-lpae", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-cloud-amd64", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-common", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-common-rt", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-loongson-3", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-marvell", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-octeon", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-powerpc64le", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rpi", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-686-pae", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-amd64", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-arm64", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-rt-armmp", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-headers-4.19.0-5-s390x", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-4kc-malta", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-4kc-malta-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-5kc-malta", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-5kc-malta-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-pae-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-pae-unsigned", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-686-unsigned", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-amd64-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-amd64-unsigned", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-arm64-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-arm64-unsigned", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp-lpae", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-armmp-lpae-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-cloud-amd64-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-cloud-amd64-unsigned", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-loongson-3", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-loongson-3-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-marvell", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-marvell-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-octeon", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-octeon-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-powerpc64le", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-powerpc64le-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rpi", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rpi-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-686-pae-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-686-pae-unsigned", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-amd64-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-amd64-unsigned", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-arm64-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-arm64-unsigned", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-armmp", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-rt-armmp-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-s390x", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-4.19.0-5-s390x-dbg", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-amd64-signed-template", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-arm64-signed-template", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-image-i386-signed-template", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-kbuild-4.19", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-libc-dev", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-perf-4.19", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-source-4.19", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"linux-support-4.19.0-5", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"lockdep", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"loop-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"md-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"minix-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-core-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mmc-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mouse-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-core-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"mtd-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"multipath-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nbd-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-shared-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-usb-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"nic-wireless-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"pata-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"rtc-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sata-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-core-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"scsi-nic-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"serial-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"sound-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"speakup-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"squashfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"udf-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"uinput-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"uinput-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"uinput-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-serial-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usb-storage-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"usbip", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-powerpc64le-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"xfs-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-4kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-5kc-malta-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-armmp-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-loongson-3-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-marvell-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-octeon-di", reference:"4.19.171-2")) flag++;
if (deb_check(release:"10.0", prefix:"zlib-modules-4.19.0-5-s390x-di", reference:"4.19.171-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
