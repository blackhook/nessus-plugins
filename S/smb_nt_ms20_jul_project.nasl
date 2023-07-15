#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(138471);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/27");

  script_cve_id("CVE-2020-1449");
  script_xref(name:"MSKB", value:"4484450");
  script_xref(name:"MSKB", value:"4484441");
  script_xref(name:"MSKB", value:"4484463");
  script_xref(name:"MSFT", value:"MS20-4484450");
  script_xref(name:"MSFT", value:"MS20-4484441");
  script_xref(name:"MSFT", value:"MS20-4484463");
  script_xref(name:"IAVA", value:"2020-A-0301");

  script_name(english:"Security Updates for Microsoft Project (July 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Project installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft Project software when the software fails to
    check the source markup of a file. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2020-1449)");
  # https://support.microsoft.com/en-us/help/4484450/security-update-for-project-2013-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2848e436");
  # https://support.microsoft.com/en-us/help/4484441/security-update-for-project-2016-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff1854bb");
  # https://support.microsoft.com/en-us/help/4484463/security-update-for-project-2010-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?091aa369");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484450
  -KB4484441
  -KB4484463");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
bulletin = 'MS20-07';

kbs = make_list(
  '4484441', # 2016
  '4484450', # 2013
  '4484463'  # 2010
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

project_checks = make_array(
  "14.0", make_array('sp', 2, 'version', "14.0.7254.5000", 'kb', '4484441'),
  "15.0", make_array('sp', 1, 'version', "15.0.5259.1000", 'kb', '4484463'),
  "16.0", make_nested_list(
    make_array('version', "16.0.5032.1000", 'channel', 'MSI', 'kb', '4484450'),
    # C2R
    make_array('version', '16.0.11328.20624', 'channel', 'Deferred'),
    make_array('version', '16.0.11929.20904', 'channel', 'Deferred', 'channel_version', '1908'),
    make_array('version', '16.0.12730.20602', 'channel', 'Enterprise Deferred'),
    make_array('version', '16.0.12827.20538', 'channel', 'Enterprise Deferred', 'channel_version', '2005'),
    make_array('version', '16.0.12527.20880', 'channel', 'First Release for Deferred'),
    make_array('version', '16.0.13001.20384', 'channel', 'Current'),
    # 2019
    make_array('version', '16.0.13001.20384', 'channel', '2019 Retail'),
    make_array('version', '16.0.10363.20015', 'channel', '2019 Volume')
    )
  );

if (hotfix_check_office_product(product:'Project', checks:project_checks, bulletin:bulletin))
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
