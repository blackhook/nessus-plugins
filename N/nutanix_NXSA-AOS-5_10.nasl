#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164558);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id("CVE-2019-14821", "CVE-2019-15239");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.10)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.10. It is, therefore, affected by multiple vulnerabilities
as referenced in the NXSA-AOS-5.10 advisory.

  - An out-of-bounds access issue was found in the Linux kernel, all versions through 5.3, in the way Linux
    kernel's KVM hypervisor implements the Coalesced MMIO write operation. It operates on an MMIO ring buffer
    'struct kvm_coalesced_mmio' object, wherein write indices 'ring->first' and 'ring->last' value could be
    supplied by a host user-space process. An unprivileged host user or process with access to '/dev/kvm'
    device could use this flaw to crash the host kernel, resulting in a denial of service or potentially
    escalating privileges on the system. (CVE-2019-14821)

  - In the Linux kernel, a certain net/ipv4/tcp_output.c change, which was properly incorporated into 4.16.12,
    was incorrectly backported to the earlier longterm kernels, introducing a new vulnerability that was
    potentially more severe than the issue that was intended to be fixed by backporting. Specifically, by
    adding to a write queue between disconnection and re-connection, a local attacker can trigger multiple
    use-after-free conditions. This can result in a kernel crash, or potentially in privilege escalation.
    NOTE: this affects (for example) Linux distributions that use 4.9.x longterm kernels before 4.9.190 or
    4.14.x longterm kernels before 4.14.139. (CVE-2019-15239)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?feeda9d8");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15239");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-14821");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.10', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.10 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '5.10', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.10 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
