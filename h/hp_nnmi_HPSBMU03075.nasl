#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77730);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2014-2624");
  script_xref(name:"HP", value:"HPSBMU03075");
  script_xref(name:"IAVA", value:"2014-A-0136");
  script_xref(name:"HP", value:"SSRT101519");
  script_xref(name:"HP", value:"emr_na-c04378450");

  script_name(english:"HP Network Node Manager i Remote Code Execution (HPSBMU03075)");
  script_summary(english:"Checks the version of HP Network Node Manager i.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is potentially affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Network Node Manager i (NNMi) installed on the
remote host is a version that is potentially affected by a remote code
execution vulnerability.

Note that Nessus did not check for the presence of a patch or
workaround for this issue.");
  script_set_attribute(attribute:"see_also", value:"http://support.openview.hp.com/selfsolve/document/KM01138724");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04378450
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d9f9490");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 10.0 or apply the hotfix referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP Network Node Manager I PMD Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_node_manager_i");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_nnmi_installed_windows.nasl");
  script_require_keys("Settings/ParanoidReport", "installed_sw/HP Network Node Manager i", "SMB/Registry/Enumerated");

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

if (ver !~ "^9\.(0\d?|1\d|2\d)(\.|$)") audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);

# We don't check if the hotfix has been applied.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 10.0' +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
