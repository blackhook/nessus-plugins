#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105112);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-12367",
    "CVE-2017-12368",
    "CVE-2017-12369",
    "CVE-2017-12370",
    "CVE-2017-12371",
    "CVE-2017-12372"
  );
  script_bugtraq_id(102017);
  script_xref(name:"CISCO-BUG-ID", value:"CSCve02843");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve10584");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve10591");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve10658");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve10744");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve10749");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve10762");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve10764");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve11503");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve11507");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve11532");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve11538");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve11545");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve11548");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve30208");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve30214");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve30268");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf38060");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf38077");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf38084");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf49650");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf49697");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf49707");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf57234");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg54836");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg54843");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg54850");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg54853");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg54856");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg54861");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg54867");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg54868");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvg54870");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20171129-webex-players");

  script_name(english:"Cisco WebEx WRF Player Multiple Vulnerabilities (cisco-sa-20171129-webex-players)");
  script_summary(english:"Checks DLL file version");

  script_set_attribute(attribute:"synopsis", value:
"The Cisco WebEx WRF Player installed on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco WebEx WRF Player installed on the remote host is affected by
multiple vulnerabilities. A remote attacker could exploit these by providing a user with
a malicious WRF file that in some cases could allow arbitrary code execution.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20171129-webex-players
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24ec09fc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of the WebEx client as described in
Cisco advisory cisco-sa-20171129-webex-players.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12372");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex_recording_format_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webex_player_installed.nasl");
  script_require_keys("SMB/WRF Player/path", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc"); 

if (report_paranoia < 2) audit(AUDIT_PARANOID);

path = get_kb_item_or_exit('SMB/WRF Player/path'); 

share = hotfix_path2share(path:path); 
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share); 

if (
    hotfix_is_vulnerable(file:'atdl2006.dll', version:'1032.1707.900.1400', min_version:'1028.0.0.0', path:path)
   )
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_INST_PATH_NOT_VULN, 'Cisco WebEx WRF Player', path);
}
