#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91261);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id("CVE-2016-2208");
  script_bugtraq_id(90653);
  script_xref(name:"IAVA", value:"2016-A-0169");

  script_name(english:"Symantec Antivirus Engine 20151.1.0.32 Malformed PE Header Parser Memory Access Violation (SYM16-008)");
  script_summary(english:"Checks the Symantec AVE version.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application installed on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Antivirus Engine (AVE) installed on the remote
host is 20151.1.0.32. It is, therefore, affected by a remote code
execution vulnerability due to improper parsing of malformed
portable-executable (PE) header files and executables packed with
early versions of Aspack. A remote attacker can exploit this by
convincing a user to download and scan a document or application
containing specially crafted PE header files, resulting in the
execution of arbitrary code.");
  # https://support.symantec.com/en_US/article.SYMSA1365.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62758e9c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Antivirus Engine 20151.1.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2208");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/AVE_version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

app = 'Symantec Antivirus Engine';

display_ver = get_kb_item_or_exit('Antivirus/SAVCE/AVE_version');

fixed_ver = '20151.1.1.4';

if (display_ver =~ "^20151\.1\.0\.32([^0-9]|$)")
{
  port = kb_smb_transport();

  report =
    '\n  Product           : ' + app +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
