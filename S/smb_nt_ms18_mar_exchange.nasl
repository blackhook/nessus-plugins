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
  script_id(108294);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/20");

  script_cve_id("CVE-2018-0924", "CVE-2018-0940", "CVE-2018-0941");
  script_bugtraq_id(103318, 103320, 103323);
  script_xref(name:"MSKB", value:"4073537");
  script_xref(name:"MSKB", value:"4073392");
  script_xref(name:"MSFT", value:"MS18-4073537");
  script_xref(name:"MSFT", value:"MS18-4073392");

  script_name(english:"Security Updates for Exchange (March 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    way that Microsoft Exchange Server handles URL
    redirects. If an impacted user is using Microsoft
    Exchange Outlook Web Access (OWA) Light, the
    vulnerability could allow an attacker to discover
    sensitive information that should otherwise not be
    disclosed, such as the URL of the user's OWA service.
    (CVE-2018-0924)

  - An information disclosure vulnerability exists in the
    way that Microsoft Exchange Server handles importing
    data. If an impacted user is using Microsoft Exchange
    Outlook Web Access (OWA), the vulnerability could allow
    an attacker to discover sensitive information that
    should otherwise not be disclosed.  (CVE-2018-0941)

  - An elevation of privilege vulnerability exists when
    Microsoft Exchange Outlook Web Access (OWA) fails to
    properly sanitize links presented to users. An attacker
    who successfully exploited this vulnerability could
    override the OWA interface with a fake login page and
    attempt to trick the user into disclosing sensitive
    information.  (CVE-2018-0940)");
  # https://support.microsoft.com/en-us/help/4073537/update-rollup-20-for-exchange-server-2010-service-pack-3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca485749");
  # https://support.microsoft.com/en-us/help/4073392/description-of-the-security-update-for-exchange-march-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cefa2aa");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released advisories to address these issues.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0941");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/13");

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

bulletin = 'MS18-03';
kb = "4073392";
kb2 = "4073537";
kbs = make_list(kb, kb2);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
   (release == 150 && cu != 4 && cu != 18 && cu != 19) ||
   (release == 151 && cu != 7 && cu != 8))
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (release == 140) # Exchange Server 2010 SP3
{
  fixedver = "14.3.389.0";
}

if (release == 150) # Exchange Server 2013
{
  if (cu == 4)
    fixedver = "15.0.847.59";
  else if (cu == 18)
    fixedver = "15.0.1347.5";
  else if (cu == 19)
    fixedver = "15.0.1365.3";
}
else if (release == 151) # Exchange Server 2016
{
  if (cu == 7)
    fixedver = "15.1.1261.39";
  else if (cu == 8)
    fixedver = "15.1.1415.4";
}

if (fixedver && release == 140 && hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb2))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else if (fixedver && hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb))
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

