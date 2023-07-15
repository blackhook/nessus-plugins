#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1599-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119310);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2016-2391", "CVE-2016-2392", "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858", "CVE-2016-4001", "CVE-2016-4002", "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441", "CVE-2016-4453", "CVE-2016-4454", "CVE-2016-4952", "CVE-2016-5105", "CVE-2016-5106", "CVE-2016-5107", "CVE-2016-5238", "CVE-2016-5337", "CVE-2016-5338", "CVE-2016-6351", "CVE-2016-6834", "CVE-2016-6836", "CVE-2016-6888", "CVE-2016-7116", "CVE-2016-7155", "CVE-2016-7156", "CVE-2016-7161", "CVE-2016-7170", "CVE-2016-7421", "CVE-2016-7908", "CVE-2016-7909", "CVE-2016-8577", "CVE-2016-8578", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106", "CVE-2017-10664", "CVE-2018-10839", "CVE-2018-17962", "CVE-2018-17963");

  script_name(english:"Debian DLA-1599-1 : qemu security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities were found in QEMU, a fast processor 
emulator :

CVE-2016-2391

Zuozhi Fzz discovered that eof_times in USB OHCI emulation support
could be used to cause a denial of service, via a NULL pointer
dereference.

CVE-2016-2392 / CVE-2016-2538

Qinghao Tang found a NULL pointer dereference and multiple integer
overflows in the USB Net device support that could allow local guest
OS administrators to cause a denial of service. These issues related
to remote NDIS control message handling.

CVE-2016-2841

Yang Hongke reported an infinite loop vulnerability in the NE2000 NIC
emulation support.

CVE-2016-2857

Liu Ling found a flaw in QEMU IP checksum routines. Attackers could
take advantage of this issue to cause QEMU to crash.

CVE-2016-2858

Arbitrary stack based allocation in the Pseudo Random Number Generator
(PRNG) back-end support.

CVE-2016-4001 / CVE-2016-4002

Oleksandr Bazhaniuk reported buffer overflows in the Stellaris and the
MIPSnet ethernet controllers emulation. Remote malicious users could
use these issues to cause QEMU to crash.

CVE-2016-4020

Donghai Zdh reported that QEMU incorrectly handled the access to the
Task Priority Register (TPR), allowing local guest OS administrators
to obtain sensitive information from host stack memory.

CVE-2016-4037

Du Shaobo found an infinite loop vulnerability in the USB EHCI
emulation support.

CVE-2016-4439 / CVE-2016-4441 / CVE-2016-5238 / CVE-2016-5338 /
CVE-2016-6351

Li Qiang found different issues in the QEMU 53C9X Fast SCSI Controller
(FSC) emulation support, that made it possible for local guest OS
privileged users to cause denials of service or potentially execute
arbitrary code.

CVE-2016-4453 / CVE-2016-4454

Li Qiang reported issues in the QEMU VMWare VGA module handling, that
may be used to cause QEMU to crash, or to obtain host sensitive
information.

CVE-2016-4952 / CVE-2016-7421 / CVE-2016-7156

Li Qiang reported flaws in the VMware paravirtual SCSI bus emulation
support. These issues concern an out-of-bounds access and infinite
loops, that allowed local guest OS privileged users to cause a denial
of service.

CVE-2016-5105 / CVE-2016-5106 / CVE-2016-5107 / CVE-2016-5337

Li Qiang discovered several issues in the MegaRAID SAS 8708EM2 Host
Bus Adapter emulation support. These issues include stack information
leakage while reading configuration and out-of-bounds write and read.

CVE-2016-6834

Li Qiang reported an infinite loop vulnerability during packet
fragmentation in the network transport abstraction layer support.
Local guest OS privileged users could made use of this flaw to cause a
denial of service.

CVE-2016-6836 / CVE-2016-6888

Li Qiang found issues in the VMWare VMXNET3 network card emulation
support, relating to information leak and integer overflow in packet
initialisation.

CVE-2016-7116

Felix Wilhel discovered a directory traversal flaw in the Plan 9 File
System (9pfs), exploitable by local guest OS privileged users.

CVE-2016-7155

Tom Victor and Li Qiang reported an out-of-bounds read and an infinite
loop in the VMware paravirtual SCSI bus emulation support.

CVE-2016-7161

Hu Chaojian reported a heap overflow in the xlnx.xps-ethernetlite
emulation support. Privileged users in local guest OS could made use
of this to cause QEMU to crash.

CVE-2016-7170

Qinghao Tang and Li Qiang reported a flaw in the QEMU VMWare VGA
module, that could be used by privileged user in local guest OS to
cause QEMU to crash via an out-of-bounds stack memory access.

CVE-2016-7908 / CVE-2016-7909

Li Qiang reported infinite loop vulnerabilities in the ColdFire Fast
Ethernet Controller and the AMD PC-Net II (Am79C970A) emulations.
These flaws allowed local guest OS administrators to cause a denial of
service.

CVE-2016-8909

Huawei PSIRT found an infinite loop vulnerability in the Intel HDA
emulation support, relating to DMA buffer stream processing.
Privileged users in local guest OS could made use of this to cause a
denial of service.

CVE-2016-8910

Andrew Henderson reported an infinite loop in the RTL8139 ethernet
controller emulation support. Privileged users inside a local guest OS
could made use of this to cause a denial of service.

CVE-2016-9101

Li Qiang reported a memory leakage in the i8255x (PRO100) ethernet
controller emulation support.

CVE-2016-9102 / CVE-2016-9103 / CVE-2016-9104 / CVE-2016-9105 /
CVE-2016-9106 / CVE-2016-8577 / CVE-2016-8578

Li Qiang reported various Plan 9 File System (9pfs) security issues,
including host memory leakage and denial of service.

CVE-2017-10664

Denial of service in the qemu-nbd (QEMU Disk Network Block Device)
Server.

CVE-2018-10839 / CVE-2018-17962 / CVE-2018-17963

Daniel Shapira reported several integer overflows in the packet
handling in ethernet controllers emulated by QEMU. These issues could
lead to denial of service.

For Debian 8 'Jessie', these problems have been fixed in version
1:2.1+dfsg-12+deb8u8.

We recommend that you upgrade your qemu packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2018/11/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/qemu"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/01");
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
if (deb_check(release:"8.0", prefix:"qemu", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-guest-agent", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-kvm", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-arm", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-common", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-mips", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-misc", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-ppc", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-sparc", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-x86", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-binfmt", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-static", reference:"1:2.1+dfsg-12+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-utils", reference:"1:2.1+dfsg-12+deb8u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
