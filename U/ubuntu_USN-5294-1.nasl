#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5294-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158159);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id(
    "CVE-2021-4083",
    "CVE-2021-4155",
    "CVE-2021-4202",
    "CVE-2021-22600",
    "CVE-2021-39685",
    "CVE-2021-43975",
    "CVE-2022-0330",
    "CVE-2022-22942"
  );
  script_xref(name:"USN", value:"5294-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/02");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel vulnerabilities (USN-5294-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has packages installed that are affected by multiple vulnerabilities as referenced in
the USN-5294-1 advisory.

  - A double free bug in packet_set_ring() in net/packet/af_packet.c can be exploited by a local user through
    crafted syscalls to escalate privileges or deny service. We recommend upgrading kernel past the effected
    versions or rebuilding past ec6af094ea28f0f2dda1a6a33b14cd57e36a9755 (CVE-2021-22600)

  - A read-after-free memory flaw was found in the Linux kernel's garbage collection for Unix domain socket
    file handlers in the way users call close() and fget() simultaneously and can potentially trigger a race
    condition. This flaw allows a local user to crash the system or escalate their privileges on the system.
    This flaw affects Linux kernel versions prior to 5.16-rc4. (CVE-2021-4083)

  - A use-after-free flaw was found in nci_request in net/nfc/nci/core.c in NFC Controller Interface (NCI) in
    the Linux kernel. This flaw could allow a local attacker with user privileges to cause a data race problem
    while the device is getting removed, leading to a privilege escalation problem. (CVE-2021-4202)

  - In various setup methods of the USB gadget subsystem, there is a possible out of bounds write due to an
    incorrect flag check. This could lead to local escalation of privilege with no additional execution
    privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android
    kernelAndroid ID: A-210292376References: Upstream kernel (CVE-2021-39685)

  - In the Linux kernel through 5.15.2, hw_atl_utils_fw_rpc_wait in
    drivers/net/ethernet/aquantia/atlantic/hw_atl/hw_atl_utils.c allows an attacker (who can introduce a
    crafted device) to trigger an out-of-bounds write via a crafted length value. (CVE-2021-43975)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5294-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39685");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-0330");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vmwgfx Driver File Descriptor Handling Priv Esc');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-100-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-buildinfo-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-cloud-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-crashdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-100-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-headers-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-100-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-extra-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-unsigned-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-libc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-100-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-modules-extra-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-osp1-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-oem-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-source-5.4.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-100");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-100-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-100-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-5.4.0-100-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-generic-lpae-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-lowlatency-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-oem-osp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-tools-virtual-hwe-18.04-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-virtual-hwe-18.04-edge");
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
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-100-generic', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-100-generic-lpae', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-buildinfo-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-100', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-100-generic', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-common', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-cloud-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-crashdump', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-generic', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-generic-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-100', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-100-generic', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-100-generic-lpae', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-headers-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-oem-osp1', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-headers-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-100-generic', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-100-generic-lpae', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-image-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-extra-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-oem-osp1', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-100-generic', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-image-unsigned-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-image-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-libc-dev', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-100-generic', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-100-generic-lpae', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-modules-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-modules-extra-5.4.0-100-generic', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-oem', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-oem-osp1', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-oem-osp1-tools-host', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-oem-tools-host', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-source', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-source-5.4.0', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-100', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-100-generic', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-100-generic-lpae', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-tools-5.4.0-100-lowlatency', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-tools-common', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-generic-lpae-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-host', 'pkgver': '5.4.0-100.113'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-lowlatency-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-oem-osp1', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-tools-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-virtual', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-18.04', 'pkgver': '5.4.0.100.104'},
    {'osver': '20.04', 'pkgname': 'linux-virtual-hwe-18.04-edge', 'pkgver': '5.4.0.100.104'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-buildinfo-5.4.0-100-generic / etc');
}
