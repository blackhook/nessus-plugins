#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3349. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(172079);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id(
    "CVE-2022-2873",
    "CVE-2022-3545",
    "CVE-2022-3623",
    "CVE-2022-4696",
    "CVE-2022-36280",
    "CVE-2022-41218",
    "CVE-2022-45934",
    "CVE-2022-47929",
    "CVE-2023-0179",
    "CVE-2023-0240",
    "CVE-2023-0266",
    "CVE-2023-0394",
    "CVE-2023-23454",
    "CVE-2023-23455",
    "CVE-2023-23586"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"Debian DLA-3349-1 : linux-5.10 - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3349 advisory.

  - An out-of-bounds memory access flaw was found in the Linux kernel Intel's iSMT SMBus host controller
    driver in the way a user triggers the I2C_SMBUS_BLOCK_DATA (with the ioctl I2C_SMBUS) with malicious input
    data. This flaw allows a local user to crash the system. (CVE-2022-2873)

  - A vulnerability has been found in Linux Kernel and classified as critical. Affected by this vulnerability
    is the function area_cache_get of the file drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c of the
    component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this
    issue. The identifier VDB-211045 was assigned to this vulnerability. (CVE-2022-3545)

  - A vulnerability was found in Linux Kernel. It has been declared as problematic. Affected by this
    vulnerability is the function follow_page_pte of the file mm/gup.c of the component BPF. The manipulation
    leads to race condition. The attack can be launched remotely. It is recommended to apply a patch to fix
    this issue. The identifier VDB-211921 was assigned to this vulnerability. (CVE-2022-3623)

  - An out-of-bounds(OOB) memory access vulnerability was found in vmwgfx driver in
    drivers/gpu/vmxgfx/vmxgfx_kms.c in GPU component in the Linux kernel with device file '/dev/dri/renderD128
    (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing
    a denial of service(DoS). (CVE-2022-36280)

  - In drivers/media/dvb-core/dmxdev.c in the Linux kernel through 5.19.10, there is a use-after-free caused
    by refcount races, affecting dvb_demux_open and dvb_dmxdev_release. (CVE-2022-41218)

  - An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req in net/bluetooth/l2cap_core.c
    has an integer wraparound via L2CAP_CONF_REQ packets. (CVE-2022-45934)

  - There exists a use-after-free vulnerability in the Linux kernel through io_uring and the IORING_OP_SPLICE
    operation. If IORING_OP_SPLICE is missing the IO_WQ_WORK_FILES flag, which signals that the operation
    won't use current->nsproxy, so its reference counter is not increased. This assumption is not always true
    as calling io_splice on specific files will call the get_uts function which will use current->nsproxy
    leading to invalidly decreasing its reference counter later causing the use-after-free vulnerability. We
    recommend upgrading to version 5.10.160 or above (CVE-2022-4696)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with tc qdisc and tc class commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929)

  - There is a logic error in io_uring's implementation which can be used to trigger a use-after-free
    vulnerability leading to privilege escalation. In the io_prep_async_work function the assumption that the
    last io_grab_identity call cannot return false is not true, and in this case the function will use the
    init_cred or the previous linked requests identity to do operations instead of using the current identity.
    This can lead to reference counting issues causing use-after-free. We recommend upgrading past version
    5.10.161. (CVE-2023-0240)

  - A use after free vulnerability exists in the ALSA PCM package in the Linux Kernel.
    SNDRV_CTL_IOCTL_ELEM_{READ|WRITE}32 is missing locks that can be used in a use-after-free that can result
    in a priviledge escalation to gain ring0 access from the system user. We recommend upgrading past commit
    56b88b50565cd8b946a2d00b0c83927b7ebb055e (CVE-2023-0266)

  - A NULL pointer dereference flaw was found in rawv6_push_pending_frames in net/ipv6/raw.c in the network
    subcomponent in the Linux kernel. This flaw causes the system to crash. (CVE-2023-0394)

  - cbq_classify in net/sched/sch_cbq.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service (slab-out-of-bounds read) because of type confusion (non-negative numbers can sometimes
    indicate a TC_ACT_SHOT condition rather than valid classification results). (CVE-2023-23454)

  - atm_tc_enqueue in net/sched/sch_atm.c in the Linux kernel through 6.1.4 allows attackers to cause a denial
    of service because of type confusion (non-negative numbers can sometimes indicate a TC_ACT_SHOT condition
    rather than valid classification results). (CVE-2023-23455)

  - Due to a vulnerability in the io_uring subsystem, it is possible to leak kernel memory information to the
    user process. timens_install calls current_is_single_threaded to determine if the current process is
    single-threaded, but this call does not consider io_uring's io_worker threads, thus it is possible to
    insert a time namespace's vvar page to process's memory space via a page fault. When this time namespace
    is destroyed, the vvar page is also freed, but not removed from the process' memory, and a next page
    allocated by the kernel will be still available from the user-space process and can leak memory contents
    via this (read-only) use-after-free vulnerability. We recommend upgrading past version 5.10.161 or commit
    788d0824269bef539fe31a785b1517882eafed93
    https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/io_uring (CVE-2023-23586)

  - kernel: Netfilter integer overflow vulnerability in nft_payload_copy_vlan (CVE-2023-0179)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=825141");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux-5.10");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2023/dla-3349");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-2873");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3545");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-3623");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36280");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41218");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-45934");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4696");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-47929");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0179");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0240");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0266");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-0394");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23454");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23455");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-23586");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/linux-5.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-5.10 packages.

For Debian 10 buster, these problems have been fixed in version 5.10.162-1~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3623");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-0266");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.20-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-5.10.0-0.deb10.21-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.17-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.19-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.20-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-686-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-cloud-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-686-pae-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-amd64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-arm64-unsigned");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-5.10.0-0.deb10.21-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-perf-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-5.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.19");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-5.10.0-0.deb10.21");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'linux-config-5.10', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-doc-5.10', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-armmp-lpae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10-rt-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-686', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-686-pae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-armmp-lpae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-cloud-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-cloud-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-common', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-common-rt', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-686-pae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.17-rt-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-686', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-686-pae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-armmp-lpae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-cloud-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-cloud-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-common', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-common-rt', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-686-pae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.19-rt-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-686', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-686-pae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-armmp-lpae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-cloud-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-cloud-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-common', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-common-rt', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-686-pae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.20-rt-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-686', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-686-pae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-armmp-lpae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-cloud-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-cloud-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-common', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-common-rt', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-686-pae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-amd64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-arm64', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-headers-5.10.0-0.deb10.21-rt-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-686-pae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-amd64-signed-template', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-arm64-signed-template', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-armmp-lpae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-cloud-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-i386-signed-template', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-686-pae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10-rt-armmp-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-pae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-pae-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-686-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-lpae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.17-rt-armmp-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-pae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-pae-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-686-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-lpae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.19-rt-armmp-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-pae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-pae-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-686-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-lpae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-armmp-lpae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-cloud-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-686-pae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-686-pae-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.20-rt-armmp-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-pae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-pae-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-686-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp-lpae', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-armmp-lpae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-cloud-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-686-pae-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-686-pae-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-amd64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-amd64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-arm64-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-arm64-unsigned', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-armmp', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-image-5.10.0-0.deb10.21-rt-armmp-dbg', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-kbuild-5.10', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-perf-5.10', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-source-5.10', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.17', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.19', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.20', 'reference': '5.10.162-1~deb10u1'},
    {'release': '10.0', 'prefix': 'linux-support-5.10.0-0.deb10.21', 'reference': '5.10.162-1~deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-config-5.10 / linux-doc-5.10 / linux-headers-5.10-armmp / etc');
}
