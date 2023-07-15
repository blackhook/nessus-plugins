#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133208);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/01");

  script_cve_id("CVE-2020-3941");
  script_xref(name:"VMSA", value:"2020-0002");
  script_xref(name:"IAVB", value:"2020-B-0005-S");

  script_name(english:"VMware Tools 10.x < 11.0.0 Privilege Escalation (VMSA-2020-0002)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization tool suite is installed on the remote Windows host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Windows host is 10.x, which is prior to 11.0.0. It is, therefore,
affected by a race condition which may allow for privilege escalation in the virtual machine where Tools is installed.
An authenticated, local attacker can exploit this to escalate their privileges on a Windows virtual machine.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0002.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 11.0.0 or later or apply the workaround mentioned in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3941");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_tools_installed.nbin", "vmware_vsphere_detect.nbin", "vmware_esxi_detection.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Tools", "Host/ESXi/checked", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Paranoid due to lack of workaround check
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:'VMware Tools', win_local:TRUE);
constraints = [{ 'min_version' : '10.0', 'fixed_version' : '11.0.0' }];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
