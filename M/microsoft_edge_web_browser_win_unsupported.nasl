#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112152);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_xref(name:"IAVA", value:"0001-A-0554");

  script_name(english:"Microsoft Edge Legacy Browser Unsupported Version Detection");
  script_summary(english:"Checks the Microsoft Edge web browser version");

  script_set_attribute(attribute:"synopsis", value:
"The version of Microsoft Edge web browser installed on the remote host is
no longer supported.");
  script_set_attribute(attribute:"description", value:
"The remote host has an install of Microsoft Edge Legacy, a web browser, which is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d9d220f");
  # https://learn.microsoft.com/en-us/lifecycle/products/microsoft-edge-legacy
  script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/en-us/windows/microsoft-edge");
  script_set_attribute(attribute:"solution", value:"Remove Edge Legacy and install a supported web browser.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8301");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_web_browser_win_installed.nbin");
  script_require_keys("SMB/MicrosoftEdge/Version");

  exit(0);
}

include("install_func.inc");

appname = "Microsoft Edge Web Browser";
version = NULL;
path = NULL;

# Credentialed
if (get_install_count(app_name: appname))
{
  install = get_single_install(app_name:appname);
  version = install['version'];
  port = get_kb_item('SMB/transport');
  if (isnull(port)) port = 445;
}
# Uncredentialed
else
{
  version = get_kb_item("SMB/MicrosoftEdge/Version");
  port = get_kb_item("MicrosoftEdge/Version_provided_by_port");
  if (isnull(port)) port = 0;
  if (isnull(version))
  {
    audit(AUDIT_NOT_INST, "Microsoft Edge Web Browser");
  }
}

register_unsupported_product(product_name: appname,
                             cpe_base:"cpe:/a:microsoft:edge", 
                             version:version
                             );

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version  +
    '\n  EOL URL           : http://www.nessus.org/u?7d9d220f' +  
    '\n';
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);

  }
  else security_hole(port);