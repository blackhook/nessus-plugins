#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140043);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2020-3975");
  script_xref(name:"IAVA", value:"2020-A-0387");

  script_name(english:"VMware App Volumes 2.x < 2.18.6 / 4.x < 4.1.0.57 (2006) XSS");

  script_set_attribute(attribute:"synopsis", value:
"An application and VM management software on the remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMWare App Volumes installed on the remote host is 2.x prior to 2.18.6, or 4.x prior to 4.1.0.57 (2006).
It is, therefore, affected by a cross-site scripting vulnerability. A malicious actor with access to create and edit 
applications or create storage groups, may be able to inject malicious script which will be executed by a victim's 
browser when viewing.");
  # https://www.vmware.com/security/advisories/VMSA-2020-0019.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3436dec7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware App Volumes 2.18.6, 4.1.0.57 (2006) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3975");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:app_volumes");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_app_vol_mgr_installed.nbin", "vmware_app_vol_agent_installed.nbin");
  script_require_keys("installed_sw/VMware App Volumes");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
 
app_info = vcf::get_app_info(app:'VMware App Volumes');

constraints = [
  { 'min_version' : '2.0', 'fixed_version' : '2.18.6' },
  { 'min_version' : '4.0', 'fixed_version' : '4.1.0.57', 'fixed_display' : '4.1.0.57 (App Volumes 4, version 2006)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);

