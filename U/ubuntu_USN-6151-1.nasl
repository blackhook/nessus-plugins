#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6151-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177051);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/09");

  script_cve_id(
    "CVE-2021-3669",
    "CVE-2022-2196",
    "CVE-2022-4382",
    "CVE-2023-23559"
  );
  script_xref(name:"USN", value:"6151-1");

  script_name(english:"Ubuntu 20.04 LTS : Linux kernel (Xilinx ZynqMP) vulnerabilities (USN-6151-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as referenced in
the USN-6151-1 advisory.

  - A flaw was found in the Linux kernel. Measuring usage of the shared memory does not scale with large
    shared memory segment counts which could lead to resource exhaustion and DoS. (CVE-2021-3669)

  - A regression exists in the Linux Kernel within KVM: nVMX that allowed for speculative execution attacks.
    L2 can carry out Spectre v2 attacks on L1 due to L1 thinking it doesn't need retpolines or IBPB after
    running L2 due to KVM (L0) advertising eIBRS support to L1. An attacker at L2 with code execution can
    execute code on an indirect branch on the host machine. We recommend upgrading to Kernel 6.2 or past
    commit 2e7eab81425a (CVE-2022-2196)

  - A use-after-free flaw caused by a race among the superblock operations in the gadgetfs Linux driver was
    found. It could be triggered by yanking out a device that is running the gadgetfs side. (CVE-2022-4382)

  - In rndis_query_oid in drivers/net/wireless/rndis_wlan.c in the Linux kernel through 6.1.5, there is an
    integer overflow in an addition. (CVE-2023-23559)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6151-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23559");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2196");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1023-xilinx-zynqmp");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023 Canonical, Inc. / NASL script (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');
include('ksplice.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var kernel_mappings = {
  '20.04': {
    '5.4.0': {
      'xilinx-zynqmp': '5.4.0-1023'
    }
  }
};

var host_kernel_release = get_kb_item_or_exit('Host/uname-r');
var host_kernel_version = get_kb_item_or_exit('Host/Debian/kernel-version');
var host_kernel_base_version = get_kb_item_or_exit('Host/Debian/kernel-base-version');
var host_kernel_type = get_kb_item_or_exit('Host/Debian/kernel-type');
if(empty_or_null(kernel_mappings[os_release][host_kernel_base_version][host_kernel_type])) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + host_kernel_release);

var extra = '';
var kernel_fixed_version = kernel_mappings[os_release][host_kernel_base_version][host_kernel_type];
if (deb_ver_cmp(ver1:host_kernel_version, ver2:kernel_fixed_version) < 0)
{
  extra = extra + 'Running Kernel level of ' + host_kernel_version + ' does not meet the minimum fixed level of ' + kernel_fixed_version + ' for this advisory.\n\n';
}
  else
{
  audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6151-1');
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2021-3669', 'CVE-2022-2196', 'CVE-2022-4382', 'CVE-2023-23559');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6151-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
