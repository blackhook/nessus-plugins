#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-5830-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170735);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/27");

  script_cve_id(
    "CVE-2022-3643",
    "CVE-2022-42896",
    "CVE-2022-43945",
    "CVE-2022-45934"
  );
  script_xref(name:"USN", value:"5830-1");

  script_name(english:"Ubuntu 18.04 LTS / 20.04 LTS : Linux kernel vulnerabilities (USN-5830-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 18.04 LTS / 20.04 LTS host has a package installed that is affected by multiple vulnerabilities as
referenced in the USN-5830-1 advisory.

  - Guests can trigger NIC interface reset/abort/crash via netback It is possible for a guest to trigger a NIC
    interface reset/abort/crash in a Linux based network backend by sending certain kinds of packets. It
    appears to be an (unwritten?) assumption in the rest of the Linux network stack that packet protocol
    headers are all contained within the linear section of the SKB and some NICs behave badly if this is not
    the case. This has been reported to occur with Cisco (enic) and Broadcom NetXtrem II BCM5780 (bnx2x)
    though it may be an issue with other NICs/drivers as well. In case the frontend is sending requests with
    split headers, netback will forward those violating above mentioned assumption to the networking core,
    resulting in said misbehavior. (CVE-2022-3643)

  - There are use-after-free vulnerabilities in the Linux kernel's net/bluetooth/l2cap_core.c's l2cap_connect
    and l2cap_le_connect_req functions which may allow code execution and leaking kernel memory (respectively)
    remotely via Bluetooth. A remote attacker could execute code leaking kernel memory via Bluetooth if within
    proximity of the victim. We recommend upgrading past commit https://www.google.com/url
    https://github.com/torvalds/linux/commit/711f8c3fb3db61897080468586b970c87c61d9e4
    https://www.google.com/url (CVE-2022-42896)

  - The Linux kernel NFSD implementation prior to versions 5.19.17 and 6.0.2 are vulnerable to buffer
    overflow. NFSD tracks the number of pages held by each NFSD thread by combining the receive and send
    buffers of a remote procedure call (RPC) into a single array of pages. A client can force the send buffer
    to shrink by sending an RPC message over TCP with garbage data added at the end of the message. The RPC
    message with garbage data is still correctly formed according to the specification and is passed forward
    to handlers. Vulnerable code in NFSD is not expecting the oversized request and writes beyond the
    allocated buffer space. CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H (CVE-2022-43945)

  - An issue was discovered in the Linux kernel through 6.0.10. l2cap_config_req in net/bluetooth/l2cap_core.c
    has an integer wraparound via L2CAP_CONF_REQ packets. (CVE-2022-45934)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-5830-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-3643");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-4.15.0-1126-raspi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-5.4.0-1101-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:linux-image-raspi2");
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
  if (! preg(pattern:"^(4.15.0-\d{4}-raspi2|5.4.0-\d{4}-azure)$", string:machine_kernel_release)) audit(AUDIT_INST_VER_NOT_VULN, 'kernel ' + machine_kernel_release);
  var extra = '';
  var kernel_mappings = {
    "4.15.0-\d{4}-raspi2" : "4.15.0-1126",
    "5.4.0-\d{4}-azure" : "5.4.0-1101"
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
        audit(AUDIT_PATCH_INSTALLED, 'Kernel package for USN-5830-1');
      }
    }
  }
}

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  var cve_list = make_list('CVE-2022-3643', 'CVE-2022-42896', 'CVE-2022-43945', 'CVE-2022-45934');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for USN-5830-1');
  }
  else
  {
    extra = extra + ksplice_reporting_text();
  }
}
if (extra) {
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
