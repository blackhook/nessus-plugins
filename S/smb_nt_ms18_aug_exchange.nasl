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
  script_id(111755);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id("CVE-2018-8302", "CVE-2018-8374");
  script_bugtraq_id(104973, 104993);
  script_xref(name:"MSKB", value:"4340731");
  script_xref(name:"MSKB", value:"4340733");
  script_xref(name:"MSFT", value:"MS18-4340731");
  script_xref(name:"MSFT", value:"MS18-4340733");

  script_name(english:"Security Updates for Exchange (August 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Exchange software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the System user. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts. Exploitation of the
    vulnerability requires that a specially crafted email be
    sent to a vulnerable Exchange server. The security
    update addresses the vulnerability by correcting how
    Microsoft Exchange handles objects in memory.
    (CVE-2018-8302)

  - A tampering vulnerability exists when Microsoft Exchange
    Server fails to properly handle profile data. An
    attacker who successfully exploited this vulnerability
    could modify a targeted user's profile data.
    (CVE-2018-8374)");
  # https://support.microsoft.com/en-us/help/4340731/description-of-the-security-update-for-microsoft-exchange-server-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?daef159c");
  # https://support.microsoft.com/en-us/help/4340733/update-rollup-23-for-exchange-server-2010-service-pack-3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9ef5fbd");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4340731
  -KB4340733");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8302");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/15");

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

bulletin = 'MS18-08';
kb = "4340731";
kb2 = "4340733";
kbs = make_list(kb, kb2);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

install = get_single_install(app_name:"Microsoft Exchange");

path = install["path"];
version = install["version"];
release = install["RELEASE"];

if (release != 140 && release != 150 && release != 151)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (!empty_or_null(install["SP"]))
  sp = install["SP"];
if (!empty_or_null(install["CU"]))
  cu = install["CU"];

if ((release == 140 && sp != 3) ||
   (release == 150 && cu != 20 && cu != 21) ||
   (release == 151 && cu != 9 && cu != 10))
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (release == 140) # Exchange Server 2010 SP3
  fixedver = "14.3.417.1";

if (release == 150) # Exchange Server 2013
{
  if (cu == 20)
    fixedver = "15.0.1367.9";
  else if (cu == 21)
    fixedver = "15.0.1395.7";
}
else if (release == 151) # Exchange Server 2016
{
  if (cu == 9)
    fixedver = "15.1.1466.10";
  else if (cu == 10)
    fixedver = "15.1.1531.6";
}

if (fixedver && release == 140 && hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb2))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else if (fixedver && hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

