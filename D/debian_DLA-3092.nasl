#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3092. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(164672);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2022-2132");

  script_name(english:"Debian DLA-3092-1 : dpdk - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3092
advisory.

  - A permissive list of allowed inputs flaw was found in DPDK. This issue allows a remote attacker to cause a
    denial of service triggered by sending a crafted Vhost header to DPDK. (CVE-2022-2132)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/dpdk");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2022/dla-3092");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2132");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/dpdk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the dpdk packages.

For Debian 10 buster, this problem has been fixed in version 18.11.11-1~deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2132");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk-igb-uio-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk-rte-kni-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-acl18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bbdev18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bitratestats18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bpf18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-dpaa18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-fslmc18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-ifpga18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-pci18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-vdev18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-vmbus18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-cfgfile18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-cmdline18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-cpt18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-dpaax18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-octeontx18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-compressdev18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-cryptodev18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-distributor18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-eal18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-efd18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ethdev18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-eventdev18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-flow-classify18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-gro18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-gso18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-hash18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ip-frag18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-jobstats18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-kni18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-kvargs18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-latencystats18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-lpm18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mbuf18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-member18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-bucket18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-dpaa18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-dpaa2-18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-octeontx18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-ring18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-stack18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meter18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-metrics18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pci18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pdump18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pipeline18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-aesni-gcm18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-aesni-mb18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-af-packet18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-ark18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-atlantic18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-avf18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-avp18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-axgbe18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-bbdev-null18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-bnx2x18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-bnxt18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-bond18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-caam-jr18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-ccp18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-crypto-scheduler18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-cxgbe18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-dpaa-event18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-dpaa-sec18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-dpaa18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-dpaa2-18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-dpaa2-cmdif18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-dpaa2-event18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-dpaa2-qdma18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-dpaa2-sec18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-dsw-event18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-e1000-18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-ena18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-enetc18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-enic18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-failsafe18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-fm10k18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-i40e18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-ifc18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-ifpga-rawdev18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-ixgbe18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-kni18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-liquidio18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-mlx4-18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-mlx5-18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-netvsc18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-nfp18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-null-crypto18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-null18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-octeontx-compress18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-octeontx-crypto18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-octeontx-event18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-octeontx18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-opdl-event18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-openssl18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-pcap18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-qat18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-qede18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-ring18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-sfc18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-skeleton-event18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-skeleton-rawdev18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-softnic18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-sw-event18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-tap18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-thunderx18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-vdev-netvsc18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-vhost18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-virtio-crypto18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-virtio18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-vmxnet3-18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pmd-zlib18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-port18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-power18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-rawdev18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-reorder18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ring18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-sched18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-security18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-table18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-telemetry18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-timer18.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-vhost18.11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'dpdk', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'dpdk-dev', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'dpdk-doc', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'dpdk-igb-uio-dkms', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'dpdk-rte-kni-dkms', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'libdpdk-dev', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-acl18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-bbdev18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-bitratestats18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-bpf18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-bus-dpaa18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-bus-fslmc18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-bus-ifpga18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-bus-pci18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-bus-vdev18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-bus-vmbus18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-cfgfile18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-cmdline18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-common-cpt18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-common-dpaax18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-common-octeontx18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-compressdev18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-cryptodev18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-distributor18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-eal18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-efd18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-ethdev18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-eventdev18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-flow-classify18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-gro18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-gso18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-hash18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-ip-frag18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-jobstats18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-kni18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-kvargs18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-latencystats18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-lpm18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-mbuf18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-member18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-mempool-bucket18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-mempool-dpaa18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-mempool-dpaa2-18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-mempool-octeontx18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-mempool-ring18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-mempool-stack18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-mempool18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-meter18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-metrics18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-net18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pci18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pdump18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pipeline18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-aesni-gcm18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-aesni-mb18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-af-packet18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-ark18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-atlantic18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-avf18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-avp18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-axgbe18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-bbdev-null18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-bnx2x18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-bnxt18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-bond18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-caam-jr18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-ccp18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-crypto-scheduler18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-cxgbe18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-dpaa-event18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-dpaa-sec18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-dpaa18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-dpaa2-18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-dpaa2-cmdif18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-dpaa2-event18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-dpaa2-qdma18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-dpaa2-sec18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-dsw-event18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-e1000-18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-ena18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-enetc18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-enic18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-failsafe18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-fm10k18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-i40e18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-ifc18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-ifpga-rawdev18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-ixgbe18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-kni18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-liquidio18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-mlx4-18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-mlx5-18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-netvsc18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-nfp18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-null-crypto18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-null18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-octeontx-compress18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-octeontx-crypto18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-octeontx-event18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-octeontx18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-opdl-event18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-openssl18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-pcap18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-qat18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-qede18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-ring18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-sfc18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-skeleton-event18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-skeleton-rawdev18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-softnic18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-sw-event18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-tap18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-thunderx18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-vdev-netvsc18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-vhost18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-virtio-crypto18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-virtio18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-vmxnet3-18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-pmd-zlib18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-port18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-power18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-rawdev18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-reorder18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-ring18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-sched18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-security18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-table18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-telemetry18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-timer18.11', 'reference': '18.11.11-1~deb10u2'},
    {'release': '10.0', 'prefix': 'librte-vhost18.11', 'reference': '18.11.11-1~deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dpdk / dpdk-dev / dpdk-doc / dpdk-igb-uio-dkms / dpdk-rte-kni-dkms / etc');
}
