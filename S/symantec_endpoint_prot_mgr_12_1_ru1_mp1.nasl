#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59367);
  script_version("1.13");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2012-0294", "CVE-2012-0295");
  script_bugtraq_id(53182, 53183);

  script_name(english:"Symantec Endpoint Protection Manager < 12.1 RU1 MP1 (SYM12-008) (credentialed check)");
  script_summary(english:"Check SEP version");

  script_set_attribute(attribute:"synopsis", value:
"The endpoint management application installed on the remote Windows
host has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is less than 12.1 RU1 MP1 (12.1.1101) and has the
following vulnerabilities :

  - An arbitrary file deletion issue exists via directory 
    traversal attacks. (CVE-2012-0294)

  - A file inclusion vulnerability exists that could result 
    in arbitrary code execution as SYSTEM. (CVE-2012-0295)");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-12-145/");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2012/Aug/265");
  # https://support.symantec.com/en_US/article.SYMSA1252.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d2da8cd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection 12.1 RU1 MP1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0295");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("SMB/sep_manager/path", "SMB/sep_manager/ver");

  exit(0);
}

include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

port = kb_smb_transport();
path = get_kb_item_or_exit('SMB/sep_manager/path');
display_ver = get_kb_item_or_exit('SMB/sep_manager/ver');
ver = split(display_ver, sep:'.', keep:FALSE);

if (
  (ver[0] == 12 && ver[1] == 1 && ver[2] == 671) || # 12.1 (12.1.671)
  (ver[0] == 12 && ver[1] == 1 && ver[2] == 1000)   # 12.1 RU1 (12.1.1000)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : 12.1.1101.401 (12.1 RU1 MP1)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SEP', display_ver);

