#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88719);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-0951", "CVE-2016-0952", "CVE-2016-0953");
  script_bugtraq_id(83114);

  script_name(english:"Adobe Photoshop CC < 15.2.4 / 16.1.2 Multiple Memory Corruption Vulnerabilities (APSB16-03)");
  script_summary(english:"Checks the Photoshop version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple memory corruption vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop installed on the remote Windows host is
prior to 15.2.4 (2014.2.4) or 16.1.2 (2015.1.2). It is, therefore,
affected by multiple unspecified memory corruption issues due to
improper validation of user-supplied input. An unauthenticated, remote
attacker can exploit these issues to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb16-03.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CC version 15.2.4 (2014.2.4) / 16.1.2
(2015.1.2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0953");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("installed_sw/Adobe Photoshop");

app_name = "Adobe Photoshop";

install = get_single_install(app_name: app_name, exit_if_unknown_ver: TRUE);

product_name = install['Product'];
if ("CC" >!< product_name)
  exit(0, "Only Adobe Photoshop CC is affected.");

ver = install['version'];
path = install['path'];
ver_ui = install['display_version'];

# version < 15.2.4 Vuln
if ( ver =~ '^15' )
  fix = '15.2.4';
# 16.x < 16.1.2 Vuln
if ( ver =~ '^16' )
  fix = '16.1.2';

if (ver_compare(ver: ver, fix: fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Product           : ' + product_name +
             '\n  Path              : ' + path +
             '\n  Installed version : ' + ver_ui +
             '\n  Fixed version     : ' + fix +
             '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver_ui, path);
