#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158148);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/25");

  script_cve_id("CVE-2021-22040", "CVE-2021-22041");
  script_xref(name:"VMSA", value:"2022-0004");
  script_xref(name:"IAVA", value:"2022-A-0089");

  script_name(english:"VMware Workstation 16.0.x < 16.2.1 Multiple Vulnerabilities (VMSA-2022-0004)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is 16.0.x prior to 16.2.1. It is, therefore, affected by
multiple vulnerabilities:

  - VMware ESXi, Workstation, and Fusion contain a use-after-free vulnerability in the XHCI USB controller. A
    malicious actor with local administrative privileges on a virtual machine may exploit this issue to
    execute code as the virtual machine's VMX process running on the host. (CVE-2021-22040)

  - VMware ESXi, Workstation, and Fusion contain a double-fetch vulnerability in the UHCI USB controller. A
    malicious actor with local administrative privileges on a virtual machine may exploit this issue to
    execute code as the virtual machine's VMX process running on the host. (CVE-2021-22041)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0004.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.vmware.com/s/article/87349");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation version 16.2.1, or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22041");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl", "vmware_workstation_linux_installed.nbin");
  script_require_keys("Host/VMware Workstation/Version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

if (get_kb_item('SMB/Registry/Enumerated')) win_local = TRUE;

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:win_local);

# Cannot check if USB controllers are being used
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var constraints = [
  { 'min_version' : '16.0', 'fixed_version' : '16.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
