#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2288-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(138911);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id("CVE-2017-9503", "CVE-2019-12068", "CVE-2019-20382", "CVE-2020-10756", "CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13659", "CVE-2020-13754", "CVE-2020-13765", "CVE-2020-15863", "CVE-2020-1983", "CVE-2020-8608");
  script_xref(name:"IAVB", value:"2020-B-0041-S");

  script_name(english:"Debian DLA-2288-1 : qemu security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The following CVE(s) were reported against src:qemu :

CVE-2017-9503

QEMU (aka Quick Emulator), when built with MegaRAID SAS 8708EM2 Host
Bus Adapter emulation support, allows local guest OS privileged users
to cause a denial of service (NULL pointer dereference and QEMU
process crash) via vectors involving megasas command processing.

CVE-2019-12068

In QEMU 1:4.1-1 (1:2.8+dfsg-6+deb9u8), when executing script in
lsi_execute_script(), the LSI scsi adapter emulator advances 's->dsp'
index to read next opcode. This can lead to an infinite loop if the
next opcode is empty. Move the existing loop exit after 10k iterations
so that it covers no-op opcodes as well.

CVE-2019-20382

QEMU 4.1.0 has a memory leak in zrle_compress_data in
ui/vnc-enc-zrle.c during a VNC disconnect operation because libz is
misused, resulting in a situation where memory allocated in
deflateInit2 is not freed in deflateEnd.

CVE-2020-1983

A use after free vulnerability in ip_reass() in ip_input.c of libslirp
4.2.0 and prior releases allows crafted packets to cause a denial of
service.

CVE-2020-8608

In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c misuses snprintf
return values, leading to a buffer overflow in later code.

CVE-2020-10756

An out-of-bounds read vulnerability was found in the SLiRP networking
implementation of the QEMU emulator. This flaw occurs in the
icmp6_send_echoreply() routine while replying to an ICMP echo request,
also known as ping. This flaw allows a malicious guest to leak the
contents of the host memory, resulting in possible information
disclosure. This flaw affects versions of libslirp before 4.3.1.

CVE-2020-13361

In QEMU 5.0.0 and earlier, es1370_transfer_audio in hw/audio/es1370.c
does not properly validate the frame count, which allows guest OS
users to trigger an out-of-bounds access during an es1370_write()
operation.

CVE-2020-13362

In QEMU 5.0.0 and earlier, megasas_lookup_frame in hw/scsi/megasas.c
has an out-of-bounds read via a crafted reply_queue_head field from a
guest OS user.

CVE-2020-13659

address_space_map in exec.c in QEMU 4.2.0 can trigger a NULL pointer
dereference related to BounceBuffer.

CVE-2020-13754

hw/pci/msix.c in QEMU 4.2.0 allows guest OS users to trigger an
out-of-bounds access via a crafted address in an msi-x mmio operation.

CVE-2020-13765

rom_copy() in hw/core/loader.c in QEMU 4.1.0 does not validate the
relationship between two addresses, which allows attackers to trigger
an invalid memory copy operation.

CVE-2020-15863

Stack-based overflow in xgmac_enet_send() in hw/net/xgmac.c.

For Debian 9 stretch, these problems have been fixed in version
1:2.8+dfsg-6+deb9u10.

We recommend that you upgrade your qemu packages.

For the detailed security status of qemu please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/qemu

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/qemu"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8608");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-block-extra");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"qemu", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-block-extra", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-guest-agent", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-kvm", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-arm", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-common", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-mips", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-misc", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-ppc", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-sparc", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-x86", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user-binfmt", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user-static", reference:"1:2.8+dfsg-6+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-utils", reference:"1:2.8+dfsg-6+deb9u10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
