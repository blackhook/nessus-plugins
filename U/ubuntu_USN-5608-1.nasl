#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5608-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165016);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/17");

  script_cve_id("CVE-2022-2132");
  script_xref(name:"USN", value:"5608-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS : DPDK vulnerability (USN-5608-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS / 22.04 LTS host has packages installed that are affected by a vulnerability as
referenced in the USN-5608-1 advisory.

  - A permissive list of allowed inputs flaw was found in DPDK. This issue allows a remote attacker to cause a
    denial of service triggered by sending a crafted Vhost header to DPDK. (CVE-2022-2132)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5608-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2132");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk-igb-uio-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:dpdk-rte-kni-dkms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-acl17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-acl20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-acl22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-acc100-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-fpga-5gnr-fec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-fpga-lte-fec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-la12xx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-null22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-baseband-turbo-sw22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bbdev0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bbdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bitratestats17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bitratestats20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bitratestats22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bpf0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bpf22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-auxiliary22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-dpaa20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-dpaa22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-fslmc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-fslmc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-ifpga20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-ifpga22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-pci17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-pci20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-pci22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vdev17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vdev20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vmbus20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-bus-vmbus22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cfgfile17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cfgfile20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cfgfile22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cmdline17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cmdline20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cmdline22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-cpt20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-cpt22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-dpaax20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-dpaax22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-iavf22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-octeontx2-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-octeontx20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-qat22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-common-sfc-efx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-isal22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compress-zlib22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compressdev0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-compressdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-bcmfs22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-caam-jr22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-ccp22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-dpaa-sec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-dpaa2-sec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-ipsec-mb22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-nitrox22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-null22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-openssl22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-scheduler22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-crypto-virtio22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cryptodev17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cryptodev20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-cryptodev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-distributor17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-distributor20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-distributor22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-dpaa22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-hisilicon22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-idxd22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-ioat22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dma-skeleton22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-dmadev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eal17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eal20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eal22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-efd17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-efd20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-efd22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ethdev17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ethdev20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ethdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dlb2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dpaa2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dpaa22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-dsw22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-opdl22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-skeleton22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-event-sw22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eventdev17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eventdev20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-eventdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-fib0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-fib22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-flow-classify0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-flow-classify17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-flow-classify22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gpudev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-graph22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gro17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gro20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gro22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gso17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gso20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-gso22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-hash17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-hash20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-hash22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ip-frag17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ip-frag20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ip-frag22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ipsec0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ipsec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-jobstats17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-jobstats20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-jobstats22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kni17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kni20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kni22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kvargs17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kvargs20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-kvargs22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-latencystats17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-latencystats20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-latencystats22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-lpm17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-lpm20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-lpm22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mbuf17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mbuf20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mbuf22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-member17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-member20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-member22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-bucket20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-bucket22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-dpaa2-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-dpaa2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-dpaa20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-dpaa22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx2-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-ring17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-ring20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-ring22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-stack17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-stack20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool-stack22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-mempool22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-allpmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-baseband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-bus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-compress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-dma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-mempool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meta-raw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meter17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meter20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-meter22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-metrics17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-metrics20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-metrics22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-af-packet22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-af-xdp22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ark22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-atlantic22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-avp22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-axgbe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-bnx2x22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-bnxt22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-bond22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-cnxk22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-cxgbe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-dpaa2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-dpaa22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-e1000-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ena22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-enetc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-enetfec22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-enic22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-failsafe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-fm10k22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-hinic22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-hns3-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-i40e22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-iavf22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ice22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-igc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ionic22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ipn3ke22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ixgbe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-kni22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-liquidio22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-memif22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-mlx4-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-netvsc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-nfp22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ngbe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-null22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-octeontx-ep22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-octeontx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-pcap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-pfe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-qede22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-ring22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-sfc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-softnic22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-tap22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-thunderx22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-txgbe22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-vdev-netvsc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-vhost22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-virtio22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net-vmxnet3-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-net22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-node22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pcapng22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pci17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pci20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pci22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pdump17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pdump20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pdump22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pipeline17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pipeline20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pipeline22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-aesni-gcm20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-aesni-mb20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-af-packet17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-af-packet20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ark17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ark20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-atlantic20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-avp17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-avp20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-axgbe20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bbdev-fpga-lte-fec20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bbdev-null20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bbdev-turbo-sw20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bnx2x20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bnxt17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bnxt20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bond17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-bond20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-caam-jr20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ccp20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-crypto-scheduler17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-crypto-scheduler20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-cxgbe17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-cxgbe20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa-sec20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa2-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa2-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa2-sec20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dpaa20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-dsw-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-e1000-17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-e1000-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ena17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ena20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-enetc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-enic17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-enic20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-failsafe17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-failsafe20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-fm10k17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-fm10k20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-hinic20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-hns3-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-i40e17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-i40e20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-iavf20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ice20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ifc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-isal20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ixgbe17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ixgbe20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-kni17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-kni20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-lio17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-liquidio20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-memif20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-mlx4-17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-mlx4-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-mlx5-17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-mlx5-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-netvsc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-nfp17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-nfp20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-nitrox20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-null-crypto17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-null-crypto20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-null17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-null20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx-compress20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx-crypto20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx-ssovf17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx2-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx2-crypto20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx2-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-octeontx20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-opdl-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-openssl20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-pcap17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-pcap20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-pfe20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-qat20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-qede17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-qede20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ring17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-ring20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-sfc-efx17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-sfc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-skeleton-event17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-skeleton-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-softnic17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-softnic20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-sw-event17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-sw-event20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-tap17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-tap20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-thunderx-nicvf17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-thunderx20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-vdev-netvsc20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-vhost17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-vhost20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-virtio-crypto20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-virtio17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-virtio20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-vmxnet3-20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-vmxnet3-uio17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-pmd-zlib20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-port17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-port20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-port22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-power17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-power20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-power22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-cnxk-bphy22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-dpaa2-cmdif22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-dpaa2-qdma22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-ifpga22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-ntb22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-raw-skeleton22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-dpaa2-cmdif20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-dpaa2-qdma20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-ioat20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-ntb20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-octeontx2-dma20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev-skeleton20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rawdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rcu0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rcu22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-regex-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-regex-octeontx2-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-regexdev22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-reorder17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-reorder20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-reorder22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rib0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-rib22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ring17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ring20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-ring22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-sched17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-sched20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-sched22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-security17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-security20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-security22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-stack0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-stack22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-table17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-table20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-table22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-telemetry0.200");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-telemetry22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-timer17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-timer20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-timer22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vdpa-ifc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vdpa-mlx5-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vdpa-sfc22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vhost17.11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vhost20.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:librte-vhost22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/Ubuntu/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
var release = chomp(release);
if (! preg(pattern:"^(18\.04|20\.04|22\.04)$", string:release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04 / 22.04', 'Ubuntu ' + release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '18.04', 'pkgname': 'dpdk', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'dpdk-dev', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'dpdk-igb-uio-dkms', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'dpdk-rte-kni-dkms', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'libdpdk-dev', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-acl17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-bitratestats17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-bus-pci17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-bus-vdev17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-cfgfile17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-cmdline17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-cryptodev17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-distributor17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-eal17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-efd17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-ethdev17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-eventdev17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-flow-classify17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-gro17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-gso17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-hash17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-ip-frag17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-jobstats17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-kni17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-kvargs17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-latencystats17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-lpm17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-mbuf17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-member17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-mempool-octeontx17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-mempool-ring17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-mempool-stack17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-mempool17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-meter17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-metrics17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-net17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pci17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pdump17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pipeline17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-af-packet17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-ark17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-avp17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-bnxt17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-bond17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-crypto-scheduler17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-cxgbe17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-e1000-17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-ena17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-enic17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-failsafe17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-fm10k17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-i40e17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-ixgbe17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-kni17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-lio17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-mlx4-17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-mlx5-17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-nfp17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-null-crypto17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-null17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-octeontx-ssovf17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-octeontx17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-pcap17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-qede17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-ring17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-sfc-efx17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-skeleton-event17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-softnic17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-sw-event17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-tap17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-thunderx-nicvf17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-vhost17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-virtio17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-pmd-vmxnet3-uio17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-port17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-power17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-reorder17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-ring17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-sched17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-security17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-table17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-timer17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '18.04', 'pkgname': 'librte-vhost17.11', 'pkgver': '17.11.10-0ubuntu0.2'},
    {'osver': '20.04', 'pkgname': 'dpdk', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'dpdk-dev', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'dpdk-igb-uio-dkms', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'libdpdk-dev', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-acl20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-bbdev0.200', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-bitratestats20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-bpf0.200', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-bus-dpaa20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-bus-fslmc20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-bus-ifpga20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-bus-pci20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-bus-vdev20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-bus-vmbus20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-cfgfile20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-cmdline20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-common-cpt20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-common-dpaax20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-common-octeontx2-20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-common-octeontx20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-compressdev0.200', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-cryptodev20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-distributor20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-eal20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-efd20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-ethdev20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-eventdev20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-fib0.200', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-flow-classify0.200', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-gro20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-gso20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-hash20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-ip-frag20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-ipsec0.200', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-jobstats20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-kni20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-kvargs20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-latencystats20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-lpm20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-mbuf20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-member20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-bucket20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-dpaa2-20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-dpaa20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-octeontx2-20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-octeontx20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-ring20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-mempool-stack20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-mempool20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-meter20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-metrics20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-net20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pci20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pdump20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pipeline20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-aesni-gcm20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-aesni-mb20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-af-packet20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ark20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-atlantic20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-avp20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-axgbe20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bbdev-fpga-lte-fec20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bbdev-null20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bbdev-turbo-sw20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bnx2x20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bnxt20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-bond20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-caam-jr20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ccp20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-crypto-scheduler20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-cxgbe20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa-event20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa-sec20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa2-20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa2-event20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa2-sec20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dpaa20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-dsw-event20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-e1000-20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ena20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-enetc20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-enic20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-failsafe20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-fm10k20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-hinic20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-hns3-20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-i40e20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-iavf20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ice20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ifc20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-isal20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ixgbe20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-kni20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-liquidio20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-memif20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-mlx4-20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-mlx5-20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-netvsc20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-nfp20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-nitrox20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-null-crypto20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-null20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx-compress20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx-crypto20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx-event20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx2-20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx2-crypto20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx2-event20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-octeontx20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-opdl-event20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-openssl20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-pcap20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-pfe20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-qat20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-qede20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-ring20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-sfc20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-skeleton-event20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-softnic20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-sw-event20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-tap20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-thunderx20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-vdev-netvsc20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-vhost20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-virtio-crypto20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-virtio20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-vmxnet3-20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-pmd-zlib20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-port20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-power20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-dpaa2-cmdif20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-dpaa2-qdma20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-ioat20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-ntb20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-octeontx2-dma20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev-skeleton20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-rawdev20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-rcu0.200', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-reorder20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-rib0.200', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-ring20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-sched20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-security20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-stack0.200', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-table20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-telemetry0.200', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-timer20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '20.04', 'pkgname': 'librte-vhost20.0', 'pkgver': '19.11.13-0ubuntu0.20.04.1'},
    {'osver': '22.04', 'pkgname': 'dpdk', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'dpdk-dev', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'libdpdk-dev', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-acl22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-acc100-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-fpga-5gnr-fec22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-fpga-lte-fec22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-la12xx22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-null22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-baseband-turbo-sw22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-bbdev22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-bitratestats22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-bpf22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-bus-auxiliary22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-bus-dpaa22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-bus-fslmc22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-bus-ifpga22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-bus-pci22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-bus-vdev22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-bus-vmbus22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-cfgfile22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-cmdline22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-common-cnxk22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-common-cpt22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-common-dpaax22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-common-iavf22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-common-mlx5-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-common-octeontx2-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-common-octeontx22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-common-qat22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-common-sfc-efx22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-compress-isal22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-compress-mlx5-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-compress-octeontx22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-compress-zlib22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-compressdev22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-bcmfs22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-caam-jr22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-ccp22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-cnxk22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-dpaa-sec22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-dpaa2-sec22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-ipsec-mb22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-mlx5-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-nitrox22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-null22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-octeontx2-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-octeontx22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-openssl22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-scheduler22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-crypto-virtio22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-cryptodev22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-distributor22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-dma-cnxk22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-dma-dpaa22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-dma-hisilicon22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-dma-idxd22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-dma-ioat22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-dma-skeleton22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-dmadev22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-eal22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-efd22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-ethdev22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-event-cnxk22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-event-dlb2-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-event-dpaa2-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-event-dpaa22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-event-dsw22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-event-octeontx2-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-event-octeontx22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-event-opdl22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-event-skeleton22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-event-sw22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-eventdev22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-fib22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-flow-classify22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-gpudev22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-graph22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-gro22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-gso22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-hash22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-ip-frag22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-ipsec22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-jobstats22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-kni22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-kvargs22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-latencystats22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-lpm22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-mbuf22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-member22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-bucket22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-cnxk22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-dpaa2-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-dpaa22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-octeontx2-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-octeontx22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-ring22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-mempool-stack22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-mempool22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-all', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-allpmds', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-baseband', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-bus', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-compress', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-crypto', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-dma', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-event', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-mempool', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-net', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meta-raw', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-meter22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-metrics22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-af-packet22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-af-xdp22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-ark22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-atlantic22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-avp22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-axgbe22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-bnx2x22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-bnxt22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-bond22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-cnxk22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-cxgbe22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-dpaa2-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-dpaa22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-e1000-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-ena22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-enetc22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-enetfec22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-enic22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-failsafe22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-fm10k22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-hinic22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-hns3-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-i40e22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-iavf22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-ice22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-igc22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-ionic22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-ipn3ke22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-ixgbe22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-kni22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-liquidio22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-memif22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-mlx4-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-mlx5-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-netvsc22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-nfp22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-ngbe22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-null22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-octeontx-ep22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-octeontx2-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-octeontx22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-pcap22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-pfe22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-qede22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-ring22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-sfc22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-softnic22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-tap22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-thunderx22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-txgbe22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-vdev-netvsc22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-vhost22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-virtio22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net-vmxnet3-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-net22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-node22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-pcapng22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-pci22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-pdump22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-pipeline22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-port22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-power22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-raw-cnxk-bphy22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-raw-dpaa2-cmdif22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-raw-dpaa2-qdma22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-raw-ifpga22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-raw-ntb22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-raw-skeleton22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-rawdev22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-rcu22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-regex-mlx5-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-regex-octeontx2-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-regexdev22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-reorder22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-rib22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-ring22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-sched22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-security22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-stack22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-table22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-telemetry22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-timer22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-vdpa-ifc22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-vdpa-mlx5-22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-vdpa-sfc22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'},
    {'osver': '22.04', 'pkgname': 'librte-vhost22', 'pkgver': '21.11.2-0ubuntu0.22.04.1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
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
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dpdk / dpdk-dev / dpdk-igb-uio-dkms / dpdk-rte-kni-dkms / libdpdk-dev / etc');
}
