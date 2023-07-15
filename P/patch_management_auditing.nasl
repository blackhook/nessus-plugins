#TRUSTED 69a99e56f32cbcaecf037234cd0d00cbe22ae87f6b51db88ffeecf889c56f7050ff73830ecf1878134fc57d03d53b648e717e3ffcf9b11281c6c0b8e73fbb6bf163026f1db0715caa61aea32db412d2c7f26451af820153bc20d25eb1e6a4c9db0f92a8531b858a090c718a3c271f97783b5142e565c41b153ae265570f0a943c9cf2ddcf6db5669c7c419289985d95043f7aff431964ecd84e1ae61cffe47553c76da0eeef37d74199bfdfdb61197cf0f9eaad63f05fd02970451d5129e373841ee2601044e9bd09bc1adc96f654b09c07a441cf0a4ed9b2d39e30b587cf21eb58ce140cf14dba7ee57152b91d92e5a66ffbe1c6fab1fa38724efbdcc98b0f4c3a2be1b9a19ababec1102767ec506f226c80562893609b70d9f14130b05bc4be8a8b1598016d8125b3e71aba087f777101ded3d4ae1263ce398d7dbbddd4de30786d00b515dea72239f450cbcf65d5f52519dc2026dd53ec54481e2d80d418064680bd0a387f636b8ec349f5b5ed468434024ade789bceddc80509cfda0275c2c458972d0955e5367e7dfb888abbe39002e31bb4cb65999c780212170ac55596c14673ad3531617ac31c6897fffc532134c7a22e0495eb24e5b66bde0136236fbb8992510fe572f0b166d105fe8eaaf180f19203354c9f9d1276fbc4a1a1c93b982594e7c1912b78445a12ed4a29527dd8695a64dcd38e59f717516b4751045

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( NASL_LEVEL < 3000 ) exit(0);

if (description)
{
  script_id(64294);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/28");

  script_name(english: "Patch Management Windows Auditing Conflicts");
  script_summary(english:"Compare reporting for patch management and Nessus.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin compares the reported vulnerable Windows patches to 
find conflicts.");
  script_set_attribute(attribute:"description", value:
"This plugin compares vulnerabilities reported by Nessus and supplied 
patch management results to determine conflicts in Windows patches. 
The report will allow you to audit your patch management solution to 
determine if it is reporting properly.");
  script_set_attribute(attribute:"solution", value:"If conflicts exist, they should be resolved with updates.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");

  script_dependencies("smb_missing_msft_patches.nasl");
  if ( NASL_LEVEL >= 5200 ) script_dependencies("pluginrules.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "patch_management/ran");
  exit(0);
}

include("smb_hotfixes.inc");
include("nessusd_product_info.inc");

pm_bulletins = make_array();
pm_tools = make_array();

plugin_feed_info = nessusd_plugin_feed_info();
if(isnull(plugin_feed_info) || isnull(plugin_feed_info["PLUGIN_SET"]))
{
  plugin_feed_info = {"PLUGIN_SET": "<error>"};
}

# generate nessus missing patch list
if (!isnull(get_kb_list("SMB/Registry/Enumerated")))
{
  bulletin_list = get_kb_list("SMB/Missing/*");
  if (!isnull(bulletin_list))
  {
    foreach bulletin (keys(bulletin_list)) 
    {
      bulletin -= "SMB/Missing/";
      pm_bulletins[tolower(bulletin)] = TRUE;
    }
  }
  pm_tools["Nessus"] = pm_bulletins;
}

# generate patch management missing list
foreach tool (keys(_pmtool_names))
{
  if (isnull(get_kb_item("patch_management/"+tool))) continue;

  pm_bulletins = make_array();
  bulletin_list = get_kb_list(tool+"/missing_patch/nt/bulletin/*");
  if (!isnull(bulletin_list))
  {
    foreach bulletin (keys(bulletin_list)) 
    {
      bulletin -= tool+"/missing_patch/nt/bulletin/";
      pm_bulletins[tolower(bulletin)] = TRUE;
    }
  }
  pm_tools[_pmtool_names[tool]] = pm_bulletins;
}

# generate report
report = '';

# report conflicts
foreach var key (keys(pm_tools))
{
  tool_bulletins1 = pm_tools[key];
  foreach tool (keys(pm_tools))
  {
    if (tool == key) continue;

    report_builder = "";
    tool_bulletins2 = pm_tools[tool];
    foreach var bulletin1 (sort(keys(tool_bulletins1)))
    {
      if (isnull(tool_bulletins2[bulletin1]))
      {
        report_builder += "  " + bulletin1 + " : " + key + ' reports vulnerable , ' + tool + ' is NOT reporting vulnerable\n';
      }
    }

    if (strlen(report_builder) > 0)
    {
      report += '\n'+key+' -> '+tool+' conflicts\n';
      report += report_builder;
    }
  }
}

count = 0; #used to detect the number of patch management solutions
tool_report = "";
foreach key (keys(pm_tools))
{
  count++;
  tool_report += key + '\n';
}
if (count < 2) 
  exit(0, "There are fewer than two patch management solutions available; at least two are needed to compare.");

if (strlen(report) > 0)
{
  # report last update for each tool used
  var nessusTimestamp = '\nNessus feed : ' + plugin_feed_info["PLUGIN_SET"] + '\n';

  tool_report = '\nThe following tools were used in this scan.\n' + tool_report;
  report = tool_report + nessusTimestamp + report;

  security_hole(port:0, extra:report);
}
else
{
  tool_report = str_replace(string:tool_report, find:'\n', replace:',' );
  set_kb_item(name:"patch_management/no/conflicts" ,value:tool_report);
}

