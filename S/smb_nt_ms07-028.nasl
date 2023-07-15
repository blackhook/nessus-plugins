#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2021/08/20. Deprecated because KB931906 is no longer available for download.

include("compat.inc");

if (description)
{
 script_id(25167);
 script_version("1.38");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/02");

 script_cve_id("CVE-2007-0940");
 script_bugtraq_id(23782);
 script_xref(name:"MSFT", value:"MS07-028");
 script_xref(name:"MSKB", value:"931906");
 
 script_xref(name:"CERT", value:"866305");

 script_name(english:"MS07-028: Vulnerability in CAPICOM Could Allow Remote Code Execution (931906) (deprecated)");
 script_summary(english:"Determines the version of CAPICOM.dll");

 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"This plugin has been deprecated because KB931906 is no longer available for download.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2007/ms07-028");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:biztalk_server");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:capicom");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

exit(0, 'This plugin has been deprecated because KB931906 is no longer available for download.');

