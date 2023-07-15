#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(144450);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2020-7337");
  script_xref(name:"MCAFEE-SB", value:"SB10338");
  script_xref(name:"IAVA", value:"2020-A-0580");

  script_name(english:"McAfee VirusScan Enterprise < 8.8 Patch 16 Access Control Bypass Vulnerability (SB10338)");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus application installed on the remote Windows host is
affected by an access control bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee VirusScan Enterprise (VSE) installed on the
remote Windows host is prior to 8.8 Patch 16. It is,
therefore, affected by an access control bypass vulnerability which allows local
administrators the ability to bypass local security protections by carefully 
manipulating the code integrity checks associated with the windows defender
integration.");
  # https://kc.mcafee.com/corporate/index?page=content&id=SB10338
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ef336c3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee VirusScan Enterprise version 8.8 Patch 16.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7337");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('Antivirus/McAfee/installed');
product_name = get_kb_item_or_exit('Antivirus/McAfee/product_name');
product_version = get_kb_item_or_exit('Antivirus/McAfee/product_version');

product_path = get_kb_item_or_exit('Antivirus/McAfee/product_path');
app = 'McAfee VirusScan Enterprise';

if (app >!< product_name)
  audit(AUDIT_INST_VER_NOT_VULN, product_name);

if (product_version !~ "^8\.8\.")
  audit(AUDIT_INST_VER_NOT_VULN, product_name, product_version);

# VSE 8.8 Patch 16 -> 8.8.0.2232
# See VSE product release information, extensions, add-ons, and TIEm for VSE on
# https://kc.mcafee.com/corporate/index?page=content&id=KB51111&actp=null&viewlocale=en_US&showDraft=false&platinum_status=false&locale=en_US
fix = '8.8.0.2300';

if (ver_compare(ver:product_version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item('SMB/transport');
  if (isnull(port)) port = 445;

  order  = make_list('Installed version', 'Fixed version');
  report = make_array(order[0],product_version, order[1],fix);
  report = report_items_str(report_items:report, ordered_fields:order);
  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, product_version); 
