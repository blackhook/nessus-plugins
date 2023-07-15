#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5130. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(160629);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2021-3839", "CVE-2022-0669");

  script_name(english:"Debian DSA-5130-1 : dpdk - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5130 advisory.

  - A flaw was found in the vhost library in DPDK. Function vhost_user_set_inflight_fd() does not validate
    `msg->payload.inflight.num_queues`, possibly causing out-of-bounds memory read/write. Any software using
    DPDK vhost library may crash as a result of this vulnerability. (CVE-2021-3839)

  - A flaw was found in dpdk. This flaw allows a malicious vhost-user master to attach an unexpected number of
    fds as ancillary data to VHOST_USER_GET_INFLIGHT_FD / VHOST_USER_SET_INFLIGHT_FD messages that are not
    closed by the vhost-user slave. By sending such messages continuously, the vhost-user master exhausts
    available fd in the vhost-user slave process, leading to a denial of service. (CVE-2022-0669)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/dpdk");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2022/dsa-5130");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-3839");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-0669");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/dpdk");
  script_set_attribute(attribute:"solution", value:
"Upgrade the dpdk packages.

For the stable distribution (bullseye), these problems have been fixed in version 20.11.5-1~deb11u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3839");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdpdk-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-acl21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-acc100-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-fpga-5gnr-fec21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-fpga-lte-fec21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-null21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-baseband-turbo-sw21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bbdev21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bitratestats21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bpf21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-dpaa21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-fslmc21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-ifpga21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-pci21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-vdev21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-bus-vmbus21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-cfgfile21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-cmdline21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-cpt21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-dpaax21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-iavf21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-mlx5-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-octeontx2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-octeontx21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-qat21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-common-sfc-efx21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-compress-isal21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-compress-octeontx21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-compress-zlib21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-compressdev21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-aesni-gcm21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-aesni-mb21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-bcmfs21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-caam-jr21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-ccp21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-dpaa-sec21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-dpaa2-sec21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-kasumi21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-nitrox21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-null21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-octeontx2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-octeontx21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-openssl21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-scheduler21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-snow3g21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-virtio21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-crypto-zuc21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-cryptodev21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-distributor21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-eal21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-efd21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ethdev21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-dlb2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-dlb21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-dpaa2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-dpaa21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-dsw21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-octeontx2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-octeontx21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-opdl21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-skeleton21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-event-sw21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-eventdev21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-fib21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-flow-classify21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-graph21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-gro21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-gso21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-hash21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ip-frag21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ipsec21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-jobstats21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-kni21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-kvargs21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-latencystats21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-lpm21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mbuf21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-member21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-bucket21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-dpaa2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-dpaa21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-octeontx2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-octeontx21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-ring21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool-stack21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-mempool21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-allpmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-baseband");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-bus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-compress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-mempool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-net");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meta-raw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-meter21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-metrics21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-af-packet21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-af-xdp21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ark21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-atlantic21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-avp21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-axgbe21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-bnx2x21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-bnxt21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-bond21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-cxgbe21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-dpaa2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-dpaa21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-e1000-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ena21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-enetc21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-enic21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-failsafe21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-fm10k21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-hinic21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-hns3-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-i40e21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-iavf21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ice21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-igc21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ipn3ke21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ixgbe21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-kni21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-liquidio21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-memif21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-mlx4-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-mlx5-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-netvsc21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-nfp21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-null21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-octeontx2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-octeontx21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-pcap21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-pfe21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-qede21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-ring21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-sfc21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-softnic21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-tap21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-thunderx21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-txgbe21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-vdev-netvsc21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-vhost21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-virtio21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net-vmxnet3-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-net21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-node21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pci21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pdump21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-pipeline21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-port21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-power21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-dpaa2-cmdif21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-dpaa2-qdma21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-ifpga21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-ioat21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-ntb21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-octeontx2-dma21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-octeontx2-ep21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-raw-skeleton21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-rawdev21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-rcu21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-regex-mlx5-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-regex-octeontx2-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-regexdev21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-reorder21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-rib21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-ring21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-sched21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-security21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-stack21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-table21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-telemetry21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-timer21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-vdpa-ifc21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-vdpa-mlx5-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librte-vhost21");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'dpdk', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'dpdk-dev', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'dpdk-doc', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'libdpdk-dev', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-acl21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-baseband-acc100-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-baseband-fpga-5gnr-fec21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-baseband-fpga-lte-fec21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-baseband-null21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-baseband-turbo-sw21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-bbdev21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-bitratestats21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-bpf21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-bus-dpaa21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-bus-fslmc21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-bus-ifpga21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-bus-pci21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-bus-vdev21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-bus-vmbus21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-cfgfile21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-cmdline21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-common-cpt21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-common-dpaax21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-common-iavf21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-common-mlx5-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-common-octeontx2-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-common-octeontx21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-common-qat21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-common-sfc-efx21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-compress-isal21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-compress-octeontx21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-compress-zlib21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-compressdev21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-aesni-gcm21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-aesni-mb21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-bcmfs21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-caam-jr21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-ccp21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-dpaa-sec21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-dpaa2-sec21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-kasumi21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-nitrox21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-null21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-octeontx2-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-octeontx21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-openssl21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-scheduler21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-snow3g21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-virtio21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-crypto-zuc21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-cryptodev21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-distributor21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-eal21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-efd21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-ethdev21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-event-dlb2-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-event-dlb21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-event-dpaa2-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-event-dpaa21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-event-dsw21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-event-octeontx2-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-event-octeontx21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-event-opdl21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-event-skeleton21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-event-sw21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-eventdev21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-fib21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-flow-classify21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-graph21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-gro21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-gso21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-hash21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-ip-frag21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-ipsec21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-jobstats21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-kni21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-kvargs21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-latencystats21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-lpm21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-mbuf21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-member21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-mempool-bucket21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-mempool-dpaa2-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-mempool-dpaa21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-mempool-octeontx2-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-mempool-octeontx21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-mempool-ring21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-mempool-stack21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-mempool21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meta-all', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meta-allpmds', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meta-baseband', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meta-bus', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meta-compress', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meta-crypto', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meta-event', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meta-mempool', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meta-net', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meta-raw', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-meter21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-metrics21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-af-packet21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-af-xdp21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-ark21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-atlantic21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-avp21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-axgbe21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-bnx2x21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-bnxt21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-bond21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-cxgbe21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-dpaa2-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-dpaa21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-e1000-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-ena21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-enetc21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-enic21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-failsafe21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-fm10k21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-hinic21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-hns3-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-i40e21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-iavf21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-ice21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-igc21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-ipn3ke21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-ixgbe21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-kni21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-liquidio21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-memif21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-mlx4-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-mlx5-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-netvsc21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-nfp21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-null21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-octeontx2-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-octeontx21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-pcap21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-pfe21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-qede21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-ring21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-sfc21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-softnic21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-tap21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-thunderx21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-txgbe21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-vdev-netvsc21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-vhost21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-virtio21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net-vmxnet3-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-net21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-node21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-pci21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-pdump21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-pipeline21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-port21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-power21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-raw-dpaa2-cmdif21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-raw-dpaa2-qdma21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-raw-ifpga21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-raw-ioat21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-raw-ntb21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-raw-octeontx2-dma21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-raw-octeontx2-ep21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-raw-skeleton21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-rawdev21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-rcu21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-regex-mlx5-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-regex-octeontx2-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-regexdev21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-reorder21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-rib21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-ring21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-sched21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-security21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-stack21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-table21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-telemetry21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-timer21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-vdpa-ifc21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-vdpa-mlx5-21', 'reference': '20.11.5-1~deb11u1'},
    {'release': '11.0', 'prefix': 'librte-vhost21', 'reference': '20.11.5-1~deb11u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dpdk / dpdk-dev / dpdk-doc / libdpdk-dev / librte-acl21 / etc');
}
