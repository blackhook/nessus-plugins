#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-6094-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176228);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/23");

  script_cve_id(
    "CVE-2022-3707",
    "CVE-2023-0459",
    "CVE-2023-1075",
    "CVE-2023-1078",
    "CVE-2023-1118",
    "CVE-2023-1513",
    "CVE-2023-2162",
    "CVE-2023-32269"
  );
  script_xref(name:"USN", value:"6094-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-6094-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-6094-1 advisory.

  - A double-free memory flaw was found in the Linux kernel. The Intel GVT-g graphics driver triggers VGA card
    system resource overload, causing a fail in the intel_gvt_dma_map_guest_page function. This issue could
    allow a local user to crash the system. (CVE-2022-3707)

  - A flaw was found in the Linux Kernel. The tls_is_tx_ready() incorrectly checks for list emptiness,
    potentially accessing a type confused entry to the list_head, leaking the last byte of the confused field
    that overlaps with rec->tx_ready. (CVE-2023-1075)

  - A flaw was found in the Linux Kernel in RDS (Reliable Datagram Sockets) protocol. The
    rds_rm_zerocopy_callback() uses list_entry() on the head of a list causing a type confusion. Local user
    can trigger this with rds_message_put(). Type confusion leads to `struct rds_msg_zcopy_info *info`
    actually points to something else that is potentially controlled by local user. It is known how to trigger
    this, which causes an out of bounds access, and a lock corruption. (CVE-2023-1078)

  - A flaw use after free in the Linux kernel integrated infrared receiver/transceiver driver was found in the
    way user detaching rc device. A local user could use this flaw to crash the system or potentially escalate
    their privileges on the system. (CVE-2023-1118)

  - A flaw was found in KVM. When calling the KVM_GET_DEBUGREGS ioctl, on 32-bit systems, there might be some
    uninitialized portions of the kvm_debugregs structure that could be copied to userspace, causing an
    information leak. (CVE-2023-1513)

  - A use-after-free vulnerability was found in iscsi_sw_tcp_session_create in drivers/scsi/iscsi_tcp.c in
    SCSI sub-component in the Linux Kernel. In this flaw an attacker could leak kernel internal information.
    (CVE-2023-2162)

  - An issue was discovered in the Linux kernel before 6.1.11. In net/netrom/af_netrom.c, there is a use-
    after-free because accept is also allowed for a successfully connected AF_NETROM socket. However, in order
    for an attacker to exploit this, the system must have netrom routing configured or the attacker must have
    the CAP_NET_ADMIN capability. (CVE-2023-32269)

  - In the Linux kernel before 6.1.6, a NULL pointer dereference bug in the traffic control subsystem allows
    an unprivileged user to trigger a denial of service (system crash) via a crafted traffic control
    configuration that is set up with tc qdisc and tc class commands. This affects qdisc_graft in
    net/sched/sch_api.c. (CVE-2022-47929) (CVE-2023-0459)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-6094-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1118");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image--lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1049-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1069-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1091-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1099-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1102-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1105-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1108-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-149--generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-149--generic-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-149--lowlatency");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gke");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-gkeop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-ibm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-kvm");
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
if (! preg(pattern:"^(18\.04|20\.04)$", string:os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 18.04 / 20.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var machine_kernel_release = get_kb_item_or_exit('Host/uname-r');
if (machine_kernel_release)
{
  var kernel_pattern;
  var kernel_mappings;
  var extra = '';
  if (preg(pattern:"^18.04$", string:os_release)) {
    kernel_pattern = "^5.4.0-\d+-(azure|gcp|generic|generic-lpae|ibm|lowlatency)$";
    kernel_mappings = {
            "5.4.0-\d+(-generic|-generic-lpae|-lowlatency)" : "5.4.0-149",
            "5.4.0-\d+-azure" : "5.4.0-1108",
            "5.4.0-\d+-gcp" : "5.4.0-1105",
            "5.4.0-\d+-ibm" : "5.4.0-1049"
    };
  };
  if (preg(pattern:"^20.04$", string:os_release)) {
    kernel_pattern = "^5.4.0-\d+-(aws|azure|gcp|generic|generic-lpae|gke|gkeop|ibm|kvm|lowlatency)$";
    kernel_mappings = {
            "5.4.0-\d+(-generic|-generic-lpae|-lowlatency)" : "5.4.0-149",
            "5.4.0-\d+-aws" : "5.4.0-1102",
            "5.4.0-\d+-azure" : "5.4.0-1108",
            "5.4.0-\d+-gcp" : "5.4.0-1105",
            "5.4.0-\d+-gke" : "5.4.0-1099",
            "5.4.0-\d+-gkeop" : "5.4.0-1069",
            "5.4.0-\d+-ibm" : "5.4.0-1049",
            "5.4.0-\d+-kvm" : "5.4.0-1091"
    };
  };
  if (! preg(pattern:kernel_pattern, string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);

  var trimmed_kernel_release = ereg_replace(string:machine_kernel_release, pattern:"(-\D.*?)$", replace:'');
  foreach var kernel_regex (keys(kernel_mappings)) {
    if (preg(pattern:kernel_regex, string:machine_kernel_release)) {
      if (deb_ver_cmp(ver1:trimmed_kernel_release, ver2:kernel_mappings[kernel_regex]) < 0)
      {
        extra = extra + 'Running Kernel level of ' + trimmed_kernel_release + ' does not meet the minimum fixed level of ' + kernel_mappings[kernel_regex] + ' for this advisory.\n\n';
      }
      else
      {
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-6094-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-3707', 'CVE-2023-0459', 'CVE-2023-1075', 'CVE-2023-1078', 'CVE-2023-1118', 'CVE-2023-1513', 'CVE-2023-2162', 'CVE-2023-32269');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-6094-1');
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
