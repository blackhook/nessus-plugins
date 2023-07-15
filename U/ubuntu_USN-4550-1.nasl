#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4550-1. The text
# itself is copyright (C) Canonical, Inc. See
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140923);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id(
    "CVE-2020-14374",
    "CVE-2020-14375",
    "CVE-2020-14376",
    "CVE-2020-14377",
    "CVE-2020-14378"
  );
  script_xref(name:"USN", value:"4550-1");

  script_name(english:"Ubuntu 20.04 LTS : DPDK vulnerabilities (USN-4550-1)");
  script_summary(english:"Checks the dpkg output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-4550-1 advisory. Note that Nessus has not tested for this issue but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4550-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk-igb-uio-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-acl20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bbdev0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bitratestats20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bpf0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-dpaa20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-fslmc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-ifpga20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-pci20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vdev20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vmbus20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cfgfile20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cmdline20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-cpt20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-dpaax20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-octeontx2-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-octeontx20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compressdev0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cryptodev20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-distributor20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eal20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-efd20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ethdev20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eventdev20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-fib0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-flow-classify0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gro20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gso20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-hash20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ip-frag20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ipsec0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-jobstats20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kni20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kvargs20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-latencystats20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-lpm20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mbuf20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-member20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-bucket20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-dpaa2-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-dpaa20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx2-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-ring20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-stack20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meter20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-metrics20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pci20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pdump20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pipeline20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-aesni-gcm20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-aesni-mb20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-af-packet20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ark20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-atlantic20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-avp20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-axgbe20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bbdev-fpga-lte-fec20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bbdev-null20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bbdev-turbo-sw20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bnx2x20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bnxt20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bond20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-caam-jr20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ccp20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-crypto-scheduler20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-cxgbe20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa-sec20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa2-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa2-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa2-sec20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dsw-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-e1000-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ena20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-enetc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-enic20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-failsafe20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-fm10k20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-hinic20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-hns3-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-i40e20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-iavf20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ice20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ifc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-isal20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ixgbe20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-kni20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-liquidio20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-memif20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-mlx4-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-mlx5-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-netvsc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-nfp20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-nitrox20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-null-crypto20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-null20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx-compress20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx-crypto20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx2-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx2-crypto20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx2-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-opdl-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-openssl20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-pcap20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-pfe20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-qat20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-qede20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ring20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-sfc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-skeleton-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-softnic20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-sw-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-tap20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-thunderx20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-vdev-netvsc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-vhost20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-virtio-crypto20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-virtio20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-vmxnet3-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-zlib20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-port20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-power20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-dpaa2-cmdif20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-dpaa2-qdma20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-ioat20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-ntb20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-octeontx2-dma20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-skeleton20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rcu0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-reorder20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rib0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ring20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-sched20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-security20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-stack0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-table20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-telemetry0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-timer20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vhost20.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2020-2023 Canonical, Inc. / NASL script (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('ubuntu.inc');
include('misc_func.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
release = chomp(release);
if (! preg(pattern:"^(20\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);


pkgs = [
    {'osver': '20.04', 'pkgname': 'dpdk', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'dpdk-dev', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'dpdk-igb-uio-dkms', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'libdpdk-dev', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-acl20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-bbdev0.200', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-bitratestats20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-bpf0.200', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-bus-dpaa20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-bus-fslmc20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-bus-ifpga20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-bus-pci20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-bus-vdev20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-bus-vmbus20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-cfgfile20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-cmdline20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-common-cpt20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-common-dpaax20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-common-octeontx2-20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-common-octeontx20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-compressdev0.200', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-cryptodev20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-distributor20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-eal20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-efd20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-ethdev20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-eventdev20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-fib0.200', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-flow-classify0.200', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-gro20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-gso20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-hash20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-ip-frag20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-ipsec0.200', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-jobstats20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-kni20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-kvargs20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-latencystats20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-lpm20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-mbuf20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-member20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-bucket20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-dpaa2-20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-dpaa20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-octeontx2-20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-octeontx20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-ring20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-stack20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-mempool20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-meter20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-metrics20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-net20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pci20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pdump20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pipeline20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-aesni-gcm20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-aesni-mb20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-af-packet20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ark20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-atlantic20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-avp20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-axgbe20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bbdev-fpga-lte-fec20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bbdev-null20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bbdev-turbo-sw20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bnx2x20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bnxt20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bond20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-caam-jr20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ccp20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-crypto-scheduler20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-cxgbe20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa-event20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa-sec20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa2-20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa2-event20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa2-sec20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dsw-event20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-e1000-20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ena20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-enetc20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-enic20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-failsafe20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-fm10k20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-hinic20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-hns3-20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-i40e20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-iavf20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ice20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ifc20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-isal20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ixgbe20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-kni20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-liquidio20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-memif20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-mlx4-20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-mlx5-20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-netvsc20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-nfp20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-nitrox20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-null-crypto20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-null20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx-compress20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx-crypto20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx-event20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx2-20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx2-crypto20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx2-event20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-opdl-event20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-openssl20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-pcap20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-pfe20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-qat20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-qede20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ring20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-sfc20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-skeleton-event20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-softnic20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-sw-event20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-tap20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-thunderx20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-vdev-netvsc20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-vhost20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-virtio-crypto20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-virtio20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-vmxnet3-20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-zlib20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-port20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-power20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-dpaa2-cmdif20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-dpaa2-qdma20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-ioat20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-ntb20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-octeontx2-dma20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-skeleton20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-rcu0.200', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-reorder20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-rib0.200', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-ring20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-sched20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-security20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-stack0.200', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-table20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-telemetry0.200', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-timer20.0', 'pkgver': '19.11.3-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'librte-vhost20.0', 'pkgver': '19.11.3-0ubuntu0.2'}
];

flag = 0;
foreach package_array ( pkgs ) {
  osver = NULL;
  pkgname = NULL;
  pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dpdk / dpdk-dev / dpdk-igb-uio-dkms / libdpdk-dev / librte-acl20.0 / etc');
}