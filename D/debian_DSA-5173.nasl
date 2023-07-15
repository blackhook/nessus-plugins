#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5173. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(162703);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2021-4197",
    "CVE-2022-0494",
    "CVE-2022-0812",
    "CVE-2022-0854",
    "CVE-2022-1011",
    "CVE-2022-1012",
    "CVE-2022-1016",
    "CVE-2022-1048",
    "CVE-2022-1184",
    "CVE-2022-1195",
    "CVE-2022-1198",
    "CVE-2022-1199",
    "CVE-2022-1204",
    "CVE-2022-1205",
    "CVE-2022-1353",
    "CVE-2022-1419",
    "CVE-2022-1516",
    "CVE-2022-1652",
    "CVE-2022-1729",
    "CVE-2022-1734",
    "CVE-2022-1974",
    "CVE-2022-1975",
    "CVE-2022-2153",
    "CVE-2022-21123",
    "CVE-2022-21125",
    "CVE-2022-21166",
    "CVE-2022-23960",
    "CVE-2022-26490",
    "CVE-2022-27666",
    "CVE-2022-28356",
    "CVE-2022-28388",
    "CVE-2022-28389",
    "CVE-2022-28390",
    "CVE-2022-29581",
    "CVE-2022-30594",
    "CVE-2022-32250",
    "CVE-2022-32296",
    "CVE-2022-33981"
  );

  script_name(english:"Debian DSA-5173-1 : linux - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5173 advisory.

  - net/netfilter/nf_tables_api.c in the Linux kernel through 5.18.1 allows a local user (able to create
    user/net namespaces) to escalate privileges to root because an incorrect NFT_STATEFUL_EXPR check leads to
    a use-after-free. (CVE-2022-32250)

  - An unprivileged write to the file handler flaw in the Linux kernel's control groups and namespaces
    subsystem was found in the way users have access to some less privileged process that are controlled by
    cgroups and have higher privileged parent process. It is actually both for cgroup2 and cgroup1 versions of
    control groups. A local user could use this flaw to crash the system or escalate their privileges on the
    system. (CVE-2021-4197)

  - A kernel information leak flaw was identified in the scsi_ioctl function in drivers/scsi/scsi_ioctl.c in
    the Linux kernel. This flaw allows a local attacker with a special user privilege (CAP_SYS_ADMIN or
    CAP_SYS_RAWIO) to create issues with confidentiality. (CVE-2022-0494)

  - An information leak flaw was found in NFS over RDMA in the net/sunrpc/xprtrdma/rpc_rdma.c in the Linux
    Kernel. This flaw allows an attacker with normal user privileges to leak kernel information.
    (CVE-2022-0812)

  - A memory leak flaw was found in the Linux kernel's DMA subsystem, in the way a user calls DMA_FROM_DEVICE.
    This flaw allows a local user to read random memory from the kernel space. (CVE-2022-0854)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=922204");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5173");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-4197");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0494");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0812");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0854");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1011");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1012");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1048");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1195");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1198");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1199");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1204");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1205");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1353");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1419");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1516");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1652");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1729");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1734");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1974");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-1975");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21123");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21125");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-21166");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2153");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-23960");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-26490");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-27666");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28356");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28388");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28389");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-28390");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-29581");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-30594");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32250");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-32296");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-33981");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32250");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-1012");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hyperv-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbpf4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcpupower1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-compiler-gcc-8-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-armel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-armhf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-mips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-mips64el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-mipsel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-ppc64el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-all-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-armmlpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-4.19.0-19-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-4kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-4kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-5kc-malta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-5kc-malta-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmlpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmlpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-loongson-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-loongson-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-marvell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-marvell-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-octeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-octeon-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-powerpc64le");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-powerpc64le-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rpi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-armmdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-4.19.0-19-s390x-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-4.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-4.19.0-19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:usbip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (! preg(pattern:"^(10)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'hyperv-daemons', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'libbpf-dev', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'libbpf4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'libcpupower-dev', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'libcpupower1', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-arm', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-s390', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-compiler-gcc-8-x86', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-config-4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-cpupower', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-doc-4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-4kc-malta', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-5kc-malta', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-686', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-686-pae', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-amd64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-arm64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-armel', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-armhf', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-i386', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-mips', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-mips64el', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-mipsel', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-ppc64el', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-all-s390x', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-amd64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-arm64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-armmp', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-armmp-lpae', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-cloud-amd64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-common', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-common-rt', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-loongson-3', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-marvell', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-octeon', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-powerpc64le', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rpi', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-686-pae', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-amd64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-arm64', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-rt-armmp', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-headers-4.19.0-19-s390x', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-4kc-malta', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-4kc-malta-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-5kc-malta', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-5kc-malta-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-pae-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-pae-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-686-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-amd64-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-amd64-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-arm64-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-arm64-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-lpae', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-armmp-lpae-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-cloud-amd64-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-cloud-amd64-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-loongson-3', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-loongson-3-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-marvell', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-marvell-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-octeon', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-octeon-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-powerpc64le', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-powerpc64le-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rpi', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rpi-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-686-pae-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-686-pae-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-amd64-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-amd64-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-arm64-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-arm64-unsigned', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-armmp', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-rt-armmp-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-s390x', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-4.19.0-19-s390x-dbg', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-amd64-signed-template', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-arm64-signed-template', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-image-i386-signed-template', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-kbuild-4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-libc-dev', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-perf-4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-source-4.19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'linux-support-4.19.0-19', 'reference': '4.19.249-2'},
    {'release': '10.0', 'prefix': 'usbip', 'reference': '4.19.249-2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'hyperv-daemons / libbpf-dev / libbpf4.19 / libcpupower-dev / etc');
}
