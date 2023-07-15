##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(160939);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/13");

  script_cve_id("CVE-2022-29107");
  script_xref(name:"MSKB", value:"4484347");
  script_xref(name:"MSKB", value:"4493152");
  script_xref(name:"MSFT", value:"MS22-4484347");
  script_xref(name:"MSFT", value:"MS22-4493152");
  script_xref(name:"IAVA", value:"2022-A-0197-S");

  script_name(english:"Security Updates for Microsoft Publisher Products (May 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Publisher Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Publisher Products are missing a security update. It is, therefore, affected by the following
vulnerability:

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application.
    (CVE-2022-29107)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4484347");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493152");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484347
  -KB4493152");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29107");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS22-05';
var kbs = make_list(
  '4493152',
  '4493152'
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var port = kb_smb_transport();

var checks = make_array(
  '15.0', make_array('sp', 1, 'version', '15.0.5449.1000', 'kb', '4484347'),
  '16.0', make_nested_list(make_array('sp', 0, 'version', '16.0.5317.1000', 'channel', 'MSI', 'kb', '4493152'))
);

if (hotfix_check_office_product(product:'Publisher', checks:checks, bulletin:bulletin))
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
