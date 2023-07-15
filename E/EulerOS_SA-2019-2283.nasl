#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131349);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id(
    "CVE-2019-0136",
    "CVE-2019-16234",
    "CVE-2019-16746",
    "CVE-2019-17052",
    "CVE-2019-17053",
    "CVE-2019-17054",
    "CVE-2019-17055",
    "CVE-2019-17056",
    "CVE-2019-17075",
    "CVE-2019-17133",
    "CVE-2019-17666",
    "CVE-2019-18806",
    "CVE-2019-18809",
    "CVE-2019-18813"
  );

  script_name(english:"EulerOS 2.0 SP8 : kernel (EulerOS-SA-2019-2283)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - A memory leak in the af9005_identify_state() function
    in drivers/media/usb/dvb-usb/af9005.c in the Linux
    kernel through 5.3.9 allows attackers to cause a denial
    of service (memory consumption), aka
    CID-2289adbfa559.(CVE-2019-18809)

  - A memory leak in the dwc3_pci_probe() function in
    drivers/usb/dwc3/dwc3-pci.c in the Linux kernel through
    5.3.9 allows attackers to cause a denial of service
    (memory consumption) by triggering
    platform_device_add_properties() failures, aka
    CID-9bbfceea12a8.(CVE-2019-18813)

  - A memory leak in the ql_alloc_large_buffers() function
    in drivers/net/ethernet/qlogic/qla3xxx.c in the Linux
    kernel before 5.3.5 allows local users to cause a
    denial of service (memory consumption) by triggering
    pci_dma_mapping_error() failures, aka
    CID-1acb8f2a7a9f.(CVE-2019-18806)

  - drivers/net/wireless/intel/iwlwifi/pcie/trans.c in the
    Linux kernel 5.2.14 does not check the alloc_workqueue
    return value, leading to a NULL pointer
    dereference.(CVE-2019-16234)

  - Insufficient access control in the Intel(R)
    PROSet/Wireless WiFi Software driver before version
    21.10 may allow an unauthenticated user to potentially
    enable denial of service via adjacent
    access.(CVE-2019-0136)

  - An issue was discovered in net/wireless/nl80211.c in
    the Linux kernel through 5.2.17. It does not check the
    length of variable elements in a beacon head, leading
    to a buffer overflow.(CVE-2019-16746)

  - In the Linux kernel through 5.3.2,
    cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c
    does not reject a long SSID IE, leading to a Buffer
    Overflow.(CVE-2019-17133)

  - rtl_p2p_noa_ie in
    drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux
    kernel through 5.3.6 lacks a certain upper-bound check,
    leading to a buffer overflow.(CVE-2019-17666)

  - An issue was discovered in write_tpt_entry in
    drivers/infiniband/hw/cxgb4/mem.c in the Linux kernel
    through 5.3.2. The cxgb4 driver is directly calling
    dma_map_single (a DMA function) from a stack variable.
    This could allow an attacker to trigger a Denial of
    Service, exploitable if this driver is used on an
    architecture for which this stack/DMA interaction has
    security relevance.(CVE-2019-17075)

  - ax25_create in net/ax25/af_ax25.c in the AF_AX25
    network module in the Linux kernel through 5.3.2 does
    not enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-0614e2b73768.(CVE-2019-17052)

  - ieee802154_create in net/ieee802154/socket.c in the
    AF_IEEE802154 network module in the Linux kernel
    through 5.3.2 does not enforce CAP_NET_RAW, which means
    that unprivileged users can create a raw socket, aka
    CID-e69dbd4619e7.(CVE-2019-17053)

  - atalk_create in net/appletalk/ddp.c in the AF_APPLETALK
    network module in the Linux kernel through 5.3.2 does
    not enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-6cc03e8aa36c.(CVE-2019-17054)

  - base_sock_create in drivers/isdn/mISDN/socket.c in the
    AF_ISDN network module in the Linux kernel through
    5.3.2 does not enforce CAP_NET_RAW, which means that
    unprivileged users can create a raw socket, aka
    CID-b91ee4aa2a21.(CVE-2019-17055)

  - llcp_sock_create in net/nfc/llcp_sock.c in the AF_NFC
    network module in the Linux kernel through 5.3.2 does
    not enforce CAP_NET_RAW, which means that unprivileged
    users can create a raw socket, aka
    CID-3a359798b176.(CVE-2019-17056)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2283
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?751dbe06");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["bpftool-4.19.36-vhulk1907.1.0.h529.eulerosv2r8",
        "kernel-4.19.36-vhulk1907.1.0.h529.eulerosv2r8",
        "kernel-devel-4.19.36-vhulk1907.1.0.h529.eulerosv2r8",
        "kernel-headers-4.19.36-vhulk1907.1.0.h529.eulerosv2r8",
        "kernel-source-4.19.36-vhulk1907.1.0.h529.eulerosv2r8",
        "kernel-tools-4.19.36-vhulk1907.1.0.h529.eulerosv2r8",
        "kernel-tools-libs-4.19.36-vhulk1907.1.0.h529.eulerosv2r8",
        "perf-4.19.36-vhulk1907.1.0.h529.eulerosv2r8",
        "python-perf-4.19.36-vhulk1907.1.0.h529.eulerosv2r8",
        "python3-perf-4.19.36-vhulk1907.1.0.h529.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
