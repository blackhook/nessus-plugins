#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100961);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2012-4177");
  script_bugtraq_id(54867);
  script_xref(name:"EDB-ID", value:"20321");

  script_name(english:"Ubisoft uPlay < 2.0.4 Browser Plugin RCE");
  script_summary(english:"Checks the Ubisoft uPlay launcher version.");

  script_set_attribute(attribute:"synopsis", value:
"A game launcher application installed on the host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Ubisoft uPlay application
installed on the remote host is prior to 2.0.4. It is, therefore,
affected by a remote code execution vulnerability in the web browser
plugin due to improper validation of user-supplied input passed via
the '-orbit_exe_path' command line argument. An unauthenticated,
remote attacker can exploit this, via a specially crafted website, to
execute arbitrary code.");
  # https://forums.ubi.com/showthread.php/699940-Uplay-PC-Patch-2-0-4-Security-fix
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83487ab3");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2012/Jul/375");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ubisoft uPlay version 2.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-4177");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ubisoft uplay 2.0.3 ActiveX Control Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ubi:uplay_pc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ubisoft_uplay_installed.nbin");
  script_require_keys("installed_sw/Ubisoft uPlay");

  exit(0);
}

include("vcf.inc");

app = "Ubisoft uPlay";

port = get_kb_item("SMB/transport");
if(!port) port = 445;

app_info = vcf::get_app_info(app:app, win_local:true, port:port);

constraints = [
  { "fixed_version" : "2.0.4" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
