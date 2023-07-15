#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(131567);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2019-1209");
  script_bugtraq_id(108589);
  script_xref(name:"MSKB", value:"4515509");
  script_xref(name:"MSFT", value:"MS19-4515509");

  script_name(english:"Security Updates for Microsoft Lync Server 2013 (September 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Lync Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Lync Server installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability :

  - An information disclosure vulnerability exists in Lync
    2013. An attacker who exploited it could read arbitrary
    files on the victim's machine. To exploit the
    vulnerability, an attacker needs to instantiate a
    conference and modify the meeting link with malicious
    content and send the link to a victim. (CVE-2019-1209)");
  # https://support.microsoft.com/en-us/help/4515509/fix-for-lync-server-2013-information-disclosure-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75b6b7fe");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4515509 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1209");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_lync_server_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('misc_func.inc');
include('install_func.inc');
include('lists.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-09';
kbs = make_list('4515509');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

vuln = FALSE;
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');
lync_installs = get_installs(app_name:'Microsoft Lync', exit_if_not_found:TRUE);

if (collib::contains(lync_installs[1], item:'Microsoft Lync Server 2013', compare:function () { return _FCT_ANON_ARGS[1]['Product'] == _FCT_ANON_ARGS[0]; }))
{
  path = hotfix_append_path(path:windir, value:"Microsoft.NET\assembly\GAC_MSIL\Microsoft.Rtc.Management\v4.0_5.0.0.0__31bf3856ad364e35"); # This path should never change
  if (hotfix_check_fversion(file:'Microsoft.Rtc.Management.dll', version:'5.0.8308.1101', min_version:'5.0.8308.0', path:path, kb:'4518345', product:'Microsoft Lync Server 2013, Core Components') == HCF_OLDER)
    vuln = TRUE;
}

foreach lync_install (lync_installs[1])
{
  if (lync_install['Product'] == 'Microsoft Lync Server 2013')
  {
    path = hotfix_append_path(path:lync_install['path'], value:"Web Components\LWA\Ext\Bin");

    if (hotfix_check_fversion(file:'Lync.Client.PreAuth.dll', version:'5.0.8308.1101', min_version:'5.0.8308.0', path:path, bulletin:bulletin, kb:'4518344', product:'Microsoft Lync Server 2013, Web Components Server') == HCF_OLDER)
      vuln = TRUE;
  }
}

if (vuln)
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
