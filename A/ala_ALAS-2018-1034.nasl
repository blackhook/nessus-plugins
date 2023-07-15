#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1034.
#

include("compat.inc");

if (description)
{
  script_id(110457);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id("CVE-2017-13672", "CVE-2017-13711", "CVE-2017-15124", "CVE-2017-15268", "CVE-2018-3639", "CVE-2018-5683", "CVE-2018-7858");
  script_xref(name:"ALAS", value:"2018-1034");

  script_name(english:"Amazon Linux AMI : qemu-kvm (ALAS-2018-1034) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An out-of-bounds read access issue was found in the VGA display
emulator built into the Quick emulator (QEMU). It could occur while
reading VGA memory to update graphics display. A privileged
user/process inside guest could use this flaw to crash the QEMU
process on the host resulting in denial of service
situation.(CVE-2017-13672)

A memory leakage issue was found in the I/O channels websockets
implementation of the Quick Emulator (QEMU). It could occur while
sending screen updates to a client, which is slow to read and process
them further. A privileged guest user could use this flaw to cause a
denial of service on the host and/or potentially crash the QEMU
process instance on the host.(CVE-2017-15268)

A use-after-free issue was found in the Slirp networking
implementation of the Quick emulator (QEMU). It occurs when a Socket
referenced from multiple packets is freed while responding to a
message. A user/process could use this flaw to crash the QEMU process
on the host resulting in denial of service.(CVE-2017-13711 )

Quick Emulator (aka QEMU), when built with the Cirrus CLGD 54xx VGA
Emulator support, allows local guest OS privileged users to cause a
denial of service (out-of-bounds access and QEMU process crash) by
leveraging incorrect region calculation when updating VGA
display.(CVE-2018-7858)

VNC server implementation in Quick Emulator (QEMU) was found to be
vulnerable to an unbounded memory allocation issue, as it did not
throttle the framebuffer updates sent to its client. If the client did
not consume these updates, VNC server allocates growing memory to hold
onto this data. A malicious remote VNC client could use this flaw to
cause DoS to the server host.(CVE-2017-15124)

An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of Load & Store
instructions (a commonly used performance optimization). It relies on
the presence of a precisely-defined instruction sequence in the
privileged code as well as the fact that memory read from address to
which a recent memory write has occurred may see an older value and
subsequently cause an update into the microprocessor's data cache even
for speculatively executed instructions that never actually commit
(retire). As a result, an unprivileged attacker could use this flaw to
read privileged memory by conducting targeted cache side-channel
attacks.(CVE-2018-3639)

An out-of-bounds read access issue was found in the VGA emulator of
QEMU. It could occur in vga_draw_text routine, while updating display
area for a vnc client. A privileged user inside a guest could use this
flaw to crash the QEMU process resulting in DoS.(CVE-2018-5683)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1034.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update qemu-kvm' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-img-1.5.3-156.8.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-1.5.3-156.8.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-156.8.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-debuginfo-1.5.3-156.8.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-156.8.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img / qemu-kvm / qemu-kvm-common / qemu-kvm-debuginfo / etc");
}
