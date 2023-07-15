#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4567. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130985);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/12");

  script_cve_id("CVE-2019-14818");
  script_xref(name:"DSA", value:"4567");

  script_name(english:"Debian DSA-4567-1 : dpdk - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the vhost PMD in DPDK, a set of libraries for
fast packet processing, was affected by memory and file descriptor
leaks which could result in denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/dpdk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/dpdk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/dpdk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4567"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dpdk packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 16.11.9-1+deb9u2.

For the stable distribution (buster), this problem has been fixed in
version 18.11.2-2+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dpdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"dpdk", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dpdk-dev", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dpdk-doc", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dpdk-igb-uio-dkms", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"dpdk-rte-kni-dkms", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libdpdk-dev", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-acl18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-bbdev18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-bitratestats18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-bpf18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-bus-dpaa18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-bus-fslmc18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-bus-ifpga18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-bus-pci18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-bus-vdev18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-bus-vmbus18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-cfgfile18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-cmdline18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-common-cpt18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-common-dpaax18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-common-octeontx18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-compressdev18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-cryptodev18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-distributor18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-eal18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-efd18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-ethdev18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-eventdev18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-flow-classify18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-gro18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-gso18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-hash18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-ip-frag18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-jobstats18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-kni18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-kvargs18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-latencystats18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-lpm18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-mbuf18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-member18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-mempool-bucket18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-mempool-dpaa18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-mempool-dpaa2-18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-mempool-octeontx18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-mempool-ring18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-mempool-stack18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-mempool18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-meter18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-metrics18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-net18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pci18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pdump18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pipeline18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-aesni-gcm18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-aesni-mb18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-af-packet18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-ark18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-atlantic18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-avf18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-avp18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-axgbe18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-bbdev-null18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-bnx2x18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-bnxt18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-bond18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-caam-jr18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-ccp18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-crypto-scheduler18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-cxgbe18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-dpaa-event18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-dpaa-sec18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-dpaa18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-dpaa2-18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-dpaa2-cmdif18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-dpaa2-event18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-dpaa2-qdma18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-dpaa2-sec18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-dsw-event18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-e1000-18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-ena18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-enetc18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-enic18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-failsafe18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-fm10k18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-i40e18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-ifc18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-ifpga-rawdev18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-ixgbe18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-kni18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-liquidio18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-mlx4-18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-mlx5-18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-netvsc18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-nfp18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-null-crypto18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-null18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-octeontx-compress18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-octeontx-crypto18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-octeontx-event18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-octeontx18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-opdl-event18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-openssl18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-pcap18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-qat18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-qede18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-ring18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-sfc18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-skeleton-event18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-skeleton-rawdev18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-softnic18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-sw-event18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-tap18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-thunderx18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-vdev-netvsc18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-vhost18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-virtio-crypto18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-virtio18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-vmxnet3-18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-pmd-zlib18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-port18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-power18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-rawdev18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-reorder18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-ring18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-sched18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-security18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-table18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-telemetry18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-timer18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"librte-vhost18.11", reference:"18.11.2-2+deb10u2")) flag++;
if (deb_check(release:"9.0", prefix:"dpdk", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dpdk-dev", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dpdk-doc", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dpdk-igb-uio-dkms", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"dpdk-rte-kni-dkms", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libdpdk-dev", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libethdev4", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-acl2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-cfgfile2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-cmdline2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-cryptodev1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-cryptodev2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-distributor1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-eal2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-eal3", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-ethdev5", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-hash2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-ip-frag1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-jobstats1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-kni2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-kvargs1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-lpm2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-mbuf2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-mempool2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-meter1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-net1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pdump1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pipeline3", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-af-packet1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-bnxt1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-bond1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-cxgbe1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-e1000-1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-ena1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-enic1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-fm10k1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-i40e1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-ixgbe1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-null-crypto1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-null1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-pcap1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-qede1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-ring2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-vhost1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-virtio1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-vmxnet3-uio1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-pmd-xenvirt1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-port3", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-power1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-reorder1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-ring1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-sched1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-table2", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-timer1", reference:"16.11.9-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"librte-vhost3", reference:"16.11.9-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
