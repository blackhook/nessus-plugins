#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5729-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167767);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/22");

  script_cve_id(
    "CVE-2022-2905",
    "CVE-2022-2978",
    "CVE-2022-3028",
    "CVE-2022-3625",
    "CVE-2022-3635",
    "CVE-2022-20422",
    "CVE-2022-39190",
    "CVE-2022-40768"
  );
  script_xref(name:"USN", value:"5729-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS : Linux kernel vulnerabilities (USN-5729-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-5729-1 advisory.

  - An out-of-bounds memory read flaw was found in the Linux kernel's BPF subsystem in how a user calls the
    bpf_tail_call function with a key larger than the max_entries of the map. This flaw allows a local user to
    gain unauthorized access to data. (CVE-2022-2905)

  - A flaw use after free in the Linux kernel NILFS file system was found in the way user triggers function
    security_inode_alloc to fail with following call to function nilfs_mdt_destroy. A local user could use
    this flaw to crash the system or potentially escalate their privileges on the system. (CVE-2022-2978)

  - A race condition was found in the Linux kernel's IP framework for transforming packets (XFRM subsystem)
    when multiple calls to xfrm_probe_algs occurred simultaneously. This flaw could allow a local attacker to
    potentially trigger an out-of-bounds write or leak kernel heap memory by performing an out-of-bounds read
    and copying it into a socket. (CVE-2022-3028)

  - A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function
    devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The
    manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier
    VDB-211929 was assigned to this vulnerability. (CVE-2022-3625)

  - A vulnerability, which was classified as critical, has been found in Linux Kernel. Affected by this issue
    is the function tst_timer of the file drivers/atm/idt77252.c of the component IPsec. The manipulation
    leads to use after free. It is recommended to apply a patch to fix this issue. VDB-211934 is the
    identifier assigned to this vulnerability. (CVE-2022-3635)

  - In emulation_proc_handler of armv8_deprecated.c, there is a possible way to corrupt memory due to a race
    condition. This could lead to local escalation of privilege with no additional execution privileges
    needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android kernelAndroid
    ID: A-237540956References: Upstream kernel (CVE-2022-20422)

  - An issue was discovered in net/netfilter/nf_tables_api.c in the Linux kernel before 5.19.6. A denial of
    service can occur upon binding to an already bound chain. (CVE-2022-39190)

  - drivers/scsi/stex.c in the Linux kernel through 5.19.9 allows local users to obtain sensitive information
    from kernel memory because stex_queuecommand_lck lacks a memset for the PASSTHRU_CMD case.
    (CVE-2022-40768)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5729-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3625");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1008-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1018-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1020-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1021-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1022-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1022-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-1023-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-53-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-53-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-53-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-53-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.15.0-53-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-lowlatency-64k");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-oracle");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2022-2023 Canonical, Inc. / NASL script (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(20\.04|22\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var machine_kernel_release = get_kb_item_or_exit('Host/uname-r');
if (machine_kernel_release)
{
  if (! preg(pattern:"^(5.15.0-\d{2}-(generic|generic-64k|generic-lpae|lowlatency|lowlatency-64k)|5.15.0-\d{4}-(azure|gcp|gke|gkeop|ibm|kvm|oracle))$", string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);
  var extra = '';
  var kernel_mappings = {
    "5.15.0-\d{2}-(generic|generic-64k|generic-lpae|lowlatency|lowlatency-64k)" : "5.15.0-53",
    "5.15.0-\d{4}-azure" : "5.15.0-1023",
    "5.15.0-\d{4}-gcp" : "5.15.0-1022",
    "5.15.0-\d{4}-gke" : "5.15.0-1020",
    "5.15.0-\d{4}-gkeop" : "5.15.0-1008",
    "5.15.0-\d{4}-ibm" : "5.15.0-1018",
    "5.15.0-\d{4}-kvm" : "5.15.0-1021",
    "5.15.0-\d{4}-oracle" : "5.15.0-1022"
  };
  var trimmed_kernel_release = ereg_replace(string:machine_kernel_release, pattern:"(-\D+)$", replace:'');
  foreach var kernel_regex (keys(kernel_mappings)) {
    if (preg(pattern:kernel_regex, string:machine_kernel_release)) {
      if (deb_ver_cmp(ver1:trimmed_kernel_release, ver2:kernel_mappings[kernel_regex]) < 0)
      {
        extra = extra + 'Running Kernel level of ' + trimmed_kernel_release + ' does not meet the minimum fixed level of ' + kernel_mappings[kernel_regex] + ' for this advisory.\n\n';
      }
      else
      {
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5729-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-2905', 'CVE-2022-2978', 'CVE-2022-3028', 'CVE-2022-3625', 'CVE-2022-3635', 'CVE-2022-20422', 'CVE-2022-39190', 'CVE-2022-40768');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5729-1');
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
