#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137663);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2020-3961");
  script_xref(name:"VMSA", value:"2020-0013");
  script_xref(name:"IAVA", value:"2020-A-0265");

  script_name(english:"VMware Horizon View Client < 5.4.3 Privilege Escalation Vulnerability (VMSA-2020-0013)");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is affected by a privilege escalation vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View Client installed on the remote Windows host is prior to 5.4.3. It is, therefore, 
affected by a privilege escalation vulnerability due to folder permission configuration and unsafe loading of 
libraries. A local authenticated attacker can exploit this issue to run commands as any user. 

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2020-0013.html");
  script_set_attribute(attribute:"solution", value:
"Update to VMware Horizon View Client version 5.4.3 or later. See advisory VMSA 2020-0013 for more details.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3961");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_horizon_view_client_installed.nbin");
  script_require_keys("installed_sw/VMware Horizon View Client");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'VMware Horizon View Client', win_local:TRUE);

constraints = [
{ 'min_version' : '1.0.0', 'fixed_version' : '5.4.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
