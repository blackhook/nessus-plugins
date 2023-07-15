#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2373-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(140541);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/04");

  script_cve_id(
    "CVE-2020-13253",
    "CVE-2020-14364",
    "CVE-2020-16092",
    "CVE-2020-1711"
  );
  script_xref(name:"IAVB", value:"2020-B-0063-S");

  script_name(english:"Debian DLA-2373-1 : qemu security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The following security issues have been found in qemu, which could
potentially result in DoS and execution of arbitrary code.

CVE-2020-1711

An out-of-bounds heap buffer access flaw was found in the way the
iSCSI Block driver in QEMU handled a response coming from an iSCSI
server while checking the status of a Logical Address Block (LBA) in
an iscsi_co_block_status() routine. A remote user could use this flaw
to crash the QEMU process, resulting in a denial of service or
potential execution of arbitrary code with privileges of the QEMU
process on the host.

CVE-2020-13253

An out-of-bounds read access issue was found in the SD Memory Card
emulator of the QEMU. It occurs while performing block write commands
via sdhci_write(), if a guest user has sent 'address' which is OOB of
's->wp_groups'. A guest user/process may use this flaw to crash the
QEMU process resulting in DoS.

CVE-2020-14364

An out-of-bounds read/write access issue was found in the USB emulator
of the QEMU. It occurs while processing USB packets from a guest, when
'USBDevice->setup_len' exceeds the USBDevice->data_buf[4096], in
do_token_{in,out} routines.

CVE-2020-16092

An assertion failure can occur in the network packet processing. This
issue affects the e1000e and vmxnet3 network devices. A malicious
guest user/process could use this flaw to abort the QEMU process on
the host, resulting in a denial of service condition in
net_tx_pkt_add_raw_fragment in hw/net/net_tx_pkt.c

For Debian 9 stretch, these problems have been fixed in version
1:2.8+dfsg-6+deb9u11.

We recommend that you upgrade your qemu packages.

For the detailed security status of qemu please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/qemu

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00013.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/qemu");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/qemu");
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/14");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"qemu", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-block-extra", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-guest-agent", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-kvm", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-arm", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-common", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-mips", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-misc", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-ppc", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-sparc", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-system-x86", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user-binfmt", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-user-static", reference:"1:2.8+dfsg-6+deb9u11")) flag++;
if (deb_check(release:"9.0", prefix:"qemu-utils", reference:"1:2.8+dfsg-6+deb9u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
