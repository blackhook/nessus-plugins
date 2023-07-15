#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2019-0045.
#

include("compat.inc");

if (description)
{
  script_id(129370);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/23");

  script_cve_id("CVE-2018-10839", "CVE-2018-11806", "CVE-2018-17962", "CVE-2019-12155", "CVE-2019-6778");

  script_name(english:"OracleVM 3.4 : qemu-kvm (OVMSA-2019-0045)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  -
    kvm-slirp-fix-big-little-endian-conversion-in-ident-prot
    .patch 

  -
    kvm-slirp-ensure-there-is-enough-space-in-mbuf-to-null-t
    .patch 

  - kvm-slirp-don-t-manipulate-so_rcv-in-tcp_emu.patch
    [bz#1669066]

  - kvm-qxl-check-release-info-object.patch [bz#1712728]

  - kvm-net-Use-iov-helper-functions.patch [bz#1636415]

  -
    kvm-net-increase-buffer-size-to-accommodate-Jumbo-frame-
    .patch 

  - kvm-net-ignore-packet-size-greater-than-INT_MAX.patch
    [bz#1636415]

  - kvm-net-drop-too-large-packet-early.patch [bz#1636415]

  - kvm-PATCH-slirp-fix-buffer-overrun.patch [bz#1586251]

  - kvm-Fix-build-from-previous-commit.patch [bz#1586251]

  - kvm-slirp-remove-mbuf-m_hdr-m_dat-indirection.patch
    [bz#1586251]

  - kvm-slirp-Convert-mbufs-to-use-g_malloc-and-g_free.patch
    [bz#1586251]

  -
    kvm-slirp-correct-size-computation-while-concatenating-m
    .patch 

  - kvm-pcnet-fix-possible-buffer-overflow.patch
    [bz#1636774]

  - Resolves: bz#1586251 (CVE-2018-11806 qemu-kvm: QEMU:
    slirp: heap buffer overflow while reassembling
    fragmented datagrams [rhel-6.10.z])

  - Resolves: bz#1636415 (CVE-2018-10839 qemu-kvm: Qemu:
    ne2000: integer overflow leads to buffer overflow issue
    [rhel-6])

  - Resolves: bz#1636774 (CVE-2018-17962 qemu-kvm: Qemu:
    pcnet: integer overflow leads to buffer overflow
    [rhel-6])

  - Resolves: bz#1669066 (CVE-2019-6778 qemu-kvm: QEMU:
    slirp: heap buffer overflow in tcp_emu [rhel-6.10.z])

  - Resolves: bz#1712728 (CVE-2019-12155 qemu-kvm: QEMU:
    qxl: null pointer dereference while releasing spice
    resources [rhel-6])"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2019-September/000960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e2a341a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qemu-img package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:qemu-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"qemu-img-0.12.1.2-2.506.el6_10.5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img");
}
