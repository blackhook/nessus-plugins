#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70147);
  script_version("1.6");
  script_cvs_date("Date: 2018/07/12 19:01:17");

  script_cve_id("CVE-2012-2022");
  script_bugtraq_id(54815);
  script_xref(name:"HP", value:"HPSBMU02798");
  script_xref(name:"HP", value:"SSRT100908");
  script_xref(name:"HP", value:"emr_na-c03405705");
  script_xref(name:"IAVB", value:"2012-B-0074");

  script_name(english:"HP NNMi 8.x / 9.0x / 9.1x / 9.20 Unspecified XSS");
  script_summary(english:"Checks version of NNMi and presence of web UI.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a
cross- site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the web interface for HP Network Node
Manager i (NNMi) installed on the remote host is affected by an
unspecified cross-site scripting vulnerability.");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03405705
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e47ecda9");
  script_set_attribute(attribute:"solution", value:
"For HP Network Node Manager i (NNMi) 9.0x, 9.1x, and 9.20 apply the
appropriate hotfix provided by the vendor. For NNMi 8.x, first upgrade
to one of those versions and then apply the appropriate hotfix.
Alternatively, upgrade to version 9.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_node_manager_i");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");

  script_dependencies("hp_nnmi_installed_windows.nasl");
  script_require_keys("Settings/ParanoidReport","installed_sw/HP Network Node Manager i","SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Force windows only
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "HP Network Node Manager i";
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
ver      = install["version"];
path     = install["path"   ];
port     = get_kb_item("SMB/transport");
if(isnull(port)) port = 445;

# We don't check if the hotfix has been applied.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (ver !~ "^8\." && ver !~ "^9\.(0\d?|1\d|20)(\.|$)") audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 9.21' +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port:port);
