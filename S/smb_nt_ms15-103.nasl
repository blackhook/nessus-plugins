#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85883);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id("CVE-2015-2505", "CVE-2015-2543", "CVE-2015-2544");
  script_bugtraq_id(76595, 76596, 76598);
  script_xref(name:"MSFT", value:"MS15-103");
  script_xref(name:"MSKB", value:"3087126");

  script_name(english:"MS15-103: Vulnerabilities in Microsoft Exchange Server Could Allow Information Disclosure (3089250)");
  script_summary(english:"Checks the version of ExSetup.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Microsoft Exchange server is affected by multiple
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft Exchange server is missing a security update. It
is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists Outlook
    Web Access (OWA) due to improper handling of web
    requests. An unauthenticated, remote attacker can
    exploit this, via a specially crafted web application
    request, to see the contents of a stacktrace.
    (CVE-2015-2505)

  - Multiple spoofing vulnerabilities exist in Outlook Web
    Access (OWA) due to improper sanitization of specially
    crafted email. An unauthenticated, remote attacker can
    exploit these vulnerabilities by convincing a user to
    visit a malicious website, resulting in the disclosure
    of sensitive information. (CVE-2015-2543, CVE-2015-2544)");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-103
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de71da53");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-2505");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");

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

bulletin = 'MS15-103';
kb = '3087126';
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

install = get_single_install(app_name:"Microsoft Exchange");

path = install["path"];
version = install["version"];
release = install["RELEASE"];
if (release != 150)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);
cu = install["CU"];

# Cumulative update 4 is Service Pack 1
if (isnull(cu) || (cu != 4 && cu != 8 && cu != 9))
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (cu == 4) # 2013 SP1 AKA CU4
{
  fixedver = "15.0.847.43";
}
else if (cu == 8) # 2013 CU8
{
  fixedver = '15.0.1076.14';
}
else if (cu == 9) # 2013 CU9
{
  fixedver = '15.0.1104.08';
}
if (hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb))
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
