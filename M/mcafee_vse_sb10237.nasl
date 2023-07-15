#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110272);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/19");

  script_cve_id("CVE-2018-6674");
  script_bugtraq_id(104180);
  script_xref(name:"MCAFEE-SB", value:"SB10237");
  script_xref(name:"IAVA", value:"2018-A-0175-S");

  script_name(english:"McAfee VirusScan Enterprise < 8.8 Patch 13 Privilege Escalation Vulnerability (SB10237)");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus application installed on the remote Windows host is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee VirusScan Enterprise (VSE) installed on the
remote Windows host is prior to 8.8 Patch 13. It is, therefore,
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10237");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee VirusScan Enterprise version 8.8 Patch 13.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6674");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("Antivirus/McAfee/installed");
product_name = get_kb_item_or_exit("Antivirus/McAfee/product_name");
product_version = get_kb_item_or_exit("Antivirus/McAfee/product_version");

product_path = get_kb_item_or_exit("Antivirus/McAfee/product_path");
app = "McAfee VirusScan Enterprise";

if (app >!< product_name)
  audit(AUDIT_INST_VER_NOT_VULN, product_name);

if (product_version !~ "^8\.8\.")
  audit(AUDIT_INST_VER_NOT_VULN, product_name, product_version);

fix = '8.8.0.2114';

# Check coptcpl.dll version
dll = product_path+"coptcpl.dll";
ver = hotfix_get_fversion(path:dll);

hotfix_handle_error(error_code:ver['error'],
                    file:dll,
                    appname:app,
                    exit_on_fail:TRUE);

hotfix_check_fversion_end();

version = join(sep:".", ver["value"]);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  order  = make_list('File', 'Installed version', 'Fixed version');
  report = make_array(order[0],dll, order[1],version, order[2],fix);
  report = report_items_str(report_items:report, ordered_fields:order);
  security_report_v4(extra:report, port:port, severity:SECURITY_NOTE);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version);
