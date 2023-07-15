#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1497-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117351);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-8666", "CVE-2016-10155", "CVE-2016-2198", "CVE-2016-6833", "CVE-2016-6835", "CVE-2016-8576", "CVE-2016-8667", "CVE-2016-8669", "CVE-2016-9602", "CVE-2016-9603", "CVE-2016-9776", "CVE-2016-9907", "CVE-2016-9911", "CVE-2016-9914", "CVE-2016-9915", "CVE-2016-9916", "CVE-2016-9921", "CVE-2016-9922", "CVE-2017-10806", "CVE-2017-10911", "CVE-2017-11434", "CVE-2017-14167", "CVE-2017-15038", "CVE-2017-15289", "CVE-2017-16845", "CVE-2017-18030", "CVE-2017-18043", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5525", "CVE-2017-5526", "CVE-2017-5579", "CVE-2017-5667", "CVE-2017-5715", "CVE-2017-5856", "CVE-2017-5973", "CVE-2017-5987", "CVE-2017-6505", "CVE-2017-7377", "CVE-2017-7493", "CVE-2017-7718", "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8112", "CVE-2017-8309", "CVE-2017-8379", "CVE-2017-9330", "CVE-2017-9373", "CVE-2017-9374", "CVE-2017-9503", "CVE-2018-5683", "CVE-2018-7550");

  script_name(english:"Debian DLA-1497-1 : qemu security update (Spectre)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were found in qemu, a fast processor 
emulator :

CVE-2015-8666

Heap-based buffer overflow in QEMU when built with the
Q35-chipset-based PC system emulator

CVE-2016-2198

NULL pointer dereference in ehci_caps_write in the USB EHCI support
that may result in denial of service

CVE-2016-6833

Use after free while writing in the vmxnet3 device that could be used
to cause a denial of service

CVE-2016-6835

Buffer overflow in vmxnet_tx_pkt_parse_headers() in vmxnet3 device
that could result in denial of service

CVE-2016-8576

Infinite loop vulnerability in xhci_ring_fetch in the USB xHCI support

CVE-2016-8667 / CVE-2016-8669

Divide by zero errors in set_next_tick in the JAZZ RC4030 chipset
emulator, and in serial_update_parameters of some serial devices, that
could result in denial of service

CVE-2016-9602

Improper link following with VirtFS

CVE-2016-9603

Heap buffer overflow via vnc connection in the Cirrus CLGD 54xx VGA
emulator support

CVE-2016-9776

Infinite loop while receiving data in the ColdFire Fast Ethernet
Controller emulator

CVE-2016-9907

Memory leakage in the USB redirector usb-guest support 

CVE-2016-9911

Memory leakage in ehci_init_transfer in the USB EHCI support

CVE-2016-9914 / CVE-2016-9915 / CVE-2016-9916

Plan 9 File System (9pfs): add missing cleanup operation in
FileOperations, in the handle backend and in the proxy backend driver

CVE-2016-9921 / CVE-2016-9922

Divide by zero in cirrus_do_copy in the Cirrus CLGD 54xx VGA Emulator
support 

CVE-2016-10155

Memory leak in hw/watchdog/wdt_i6300esb.c allowing local guest OS
privileged users to cause a denial of service via a large number of
device unplug operations.

CVE-2017-2615 / CVE-2017-2620 / CVE-2017-18030 / CVE-2018-5683 /
CVE-2017-7718

Out-of-bounds access issues in the Cirrus CLGD 54xx VGA emulator
support, that could result in denial of service

CVE-2017-5525 / CVE-2017-5526

Memory leakage issues in the ac97 and es1370 device emulation

CVE-2017-5579

Most memory leakage in the 16550A UART emulation

CVE-2017-5667

Out-of-bounds access during multi block SDMA transfer in the SDHCI
emulation support.

CVE-2017-5715

Mitigations against the Spectre v2 vulnerability. For more information
please refer to https://www.qemu.org/2018/01/04/spectre/

CVE-2017-5856

Memory leak in the MegaRAID SAS 8708EM2 Host Bus Adapter emulation
support

CVE-2017-5973 / CVE-2017-5987 / CVE-2017-6505

Infinite loop issues in the USB xHCI, in the transfer mode register of
the SDHCI protocol, and the USB ohci_service_ed_list

CVE-2017-7377

9pfs: host memory leakage via v9fs_create

CVE-2017-7493

Improper access control issues in the host directory sharing via 9pfs
support.

CVE-2017-7980

Heap-based buffer overflow in the Cirrus VGA device that could allow
local guest OS users to execute arbitrary code or cause a denial of
service

CVE-2017-8086

9pfs: host memory leakage via v9pfs_list_xattr

CVE-2017-8112

Infinite loop in the VMWare PVSCSI emulation

CVE-2017-8309 / CVE-2017-8379

Host memory leakage issues via the audio capture buffer and the
keyboard input event handlers 

CVE-2017-9330

Infinite loop due to incorrect return value in USB OHCI that may
result in denial of service

CVE-2017-9373 / CVE-2017-9374

Host memory leakage during hot unplug in IDE AHCI and USB emulated
devices that could result in denial of service

CVE-2017-9503

NULL pointer dereference while processing megasas command

CVE-2017-10806

Stack buffer overflow in USB redirector

CVE-2017-10911

Xen disk may leak stack data via response ring

CVE-2017-11434

Out-of-bounds read while parsing Slirp/DHCP options

CVE-2017-14167

Out-of-bounds access while processing multiboot headers that could
result in the execution of arbitrary code

CVE-2017-15038

9pfs: information disclosure when reading extended attributes

CVE-2017-15289

Out-of-bounds write access issue in the Cirrus graphic adaptor that
could result in denial of service

CVE-2017-16845

Information leak in the PS/2 mouse and keyboard emulation support that
could be exploited during instance migration 

CVE-2017-18043

Integer overflow in the macro ROUND_UP (n, d) that could result in
denial of service

CVE-2018-7550

Incorrect handling of memory during multiboot that could may result in
execution of arbitrary code

For Debian 8 'Jessie', these problems have been fixed in version
1:2.1+dfsg-12+deb8u7.

We recommend that you upgrade your qemu packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.qemu.org/2018/01/04/spectre/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-sparc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-system-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-binfmt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/07");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"8.0", prefix:"qemu", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-guest-agent", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-kvm", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-arm", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-common", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-mips", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-misc", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-ppc", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-sparc", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-x86", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-binfmt", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-static", reference:"1:2.1+dfsg-12+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-utils", reference:"1:2.1+dfsg-12+deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
