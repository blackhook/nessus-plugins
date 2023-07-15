#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157130);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/08");

  script_cve_id("CVE-2022-22938");
  script_xref(name:"VMSA", value:"2020-0020");
  script_xref(name:"IAVA", value:"2022-A-0043");

  script_name(english:"VMware Workstation 16.x < 16.2.2 DoS (VMSA-2022-0002)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Workstation installed on the remote host is 16.x prior to 16.2.2. It is, therefore, affected by
a denial of service (DoS) vulnerability in the Cortado ThinPrint component's TrueType font parser. A local attacker can
exploit this in order to cause the ThinPrint service to stop responding.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0002.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Workstation 16.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22938");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:workstation");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_workstation_detect.nasl");
  script_require_keys("installed_sw/VMware Workstation", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'VMware Workstation', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  { 'min_version' : '16.0', 'fixed_version' : '16.2.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

