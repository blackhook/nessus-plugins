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
  script_id(119593);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id("CVE-2018-8604");
  script_xref(name:"MSKB", value:"4468741");
  script_xref(name:"MSFT", value:"MS18-4468741");

  script_name(english:"Security Updates for Exchange (December 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - A tampering vulnerability exists when Microsoft Exchange
    Server fails to properly handle profile data. An
    attacker who successfully exploited this vulnerability
    could modify a targeted user's profile data.
    (CVE-2018-8604)");
  # https://support.microsoft.com/en-us/help/4468741/security-update-for-the-exchange-tampering-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ef684df");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4468741 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8604");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

exit_if_productname_not_server();

bulletin = 'MS18-12';
kb = "4468741";
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

install = get_single_install(app_name:"Microsoft Exchange");

path = install["path"];
version = install["version"];
release = install["RELEASE"];

if (release != 151)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (!empty_or_null(install["SP"]))
  sp = install["SP"];
if (!empty_or_null(install["CU"]))
  cu = install["CU"];

if (release == 151 && cu != 10 && cu != 11)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (release == 151) # Exchange Server 2016
{
  if (cu == 10)
    fixedver = "15.1.1531.8";
  else if (cu == 11)
    fixedver = "15.1.1591.11";
}

if (fixedver && hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

