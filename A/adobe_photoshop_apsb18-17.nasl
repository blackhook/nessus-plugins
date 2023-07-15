#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109864);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id("CVE-2018-4946");
  script_bugtraq_id(104171);

  script_name(english:"Adobe Photoshop CC 18.x < 18.1.4 / 19.x < 19.1.4 Remote Code Execution Vulnerability (APSB18-17)");
  script_summary(english:"Checks the Photoshop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC installed on the remote Windows host
is 18.x prior to 18.1.4 (2017.1.4) or 19.x prior to 19.1.4 (2018.1.4).
It is, therefore, affected by an unspecified remote code execution
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb18-17.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CC 18.1.4 (2017.1.4), 19.1.4 (2018.1.4)
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4946");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Adobe Photoshop";
install  = get_single_install(app_name: app_name, exit_if_unknown_ver: TRUE);

product_name = install['Product'];
if ("CC" >!< product_name)
  exit(0, "Only Adobe Photoshop CC is affected.");

ver    = install['version'];
path   = install['path'];
ver_ui = install['display_version'];

# Version 18.x < 18.1.4 Vuln
if ( ver =~ "^18\." )
  fix = '18.1.4';
# Version 19.x < 19.1.4 Vuln
else if ( ver =~ "^19\." )
  fix = '19.1.4';
else
  audit(AUDIT_NOT_INST, app_name + " 18.x or 19.x");

if (ver_compare(ver: ver, fix: fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  report = '\n  Product           : ' + product_name +
           '\n  Path              : ' + path +
           '\n  Installed version : ' + ver_ui +
           '\n  Fixed version     : ' + fix +
           '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver_ui, path);
