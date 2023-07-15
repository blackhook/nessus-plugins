#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151012);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/30");

  script_cve_id("CVE-2021-21997");
  script_xref(name:"IAVB", value:"2021-B-0037-S");
  script_xref(name:"VMSA", value:"VMSA-2021-0011");

  script_name(english:"VMware Tools 11.x < 11.3.0 DoS (VMSA-2021-0011)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization tool suite is installed on the remote Windows host is affected by a denial-of-service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Tools installed on the remote Windows host is 11.x, which is prior to 11.3.0. It is, therefore,
affected by a denial-of-service vulnerability in the VM3DMP driver. A malicious actor with local user privileges in
the Windows guest operating system, where VMware Tools is installed, can trigger a PANIC in the VM3DMP driver leading
to a denial-of-service condition in the Windows guest operating system.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0011.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Tools version 11.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21997");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:tools");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_tools_installed.nbin", "vmware_vsphere_detect.nbin", "vmware_esxi_detection.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Tools", "Host/ESXi/checked");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit("SMB/Registry/Enumerated");

var app_info = vcf::get_app_info(app:'VMware Tools', win_local:TRUE);

var constraints = [
  { 'min_version' : '11.0', 'fixed_version' : '11.3.0' } 
  ];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
  );
