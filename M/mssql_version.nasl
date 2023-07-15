#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(11217);
 script_version("1.156");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_xref(name:"IAVT", value:"0001-T-0800");

 script_name(english:"Microsoft SQL Server Detection (credentialed check)");
 script_summary(english:"Detects Microsoft SQL Server installs.");

 script_set_attribute(attribute:"synopsis", value:"The remote host has a database server installed.");
 script_set_attribute(attribute:"description", value:
"Nessus has detected one or more installs of Microsoft SQL server by
examining the registry and file systems on the remote host.");
#https://learn.microsoft.com/en-us/troubleshoot/sql/general/determine-version-edition-update-level
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e45407e9");
 script_set_attribute(attribute:"solution", value:"Ensure the latest service pack and hotfixes are installed.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"agent", value:"windows");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/01/26");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
 script_set_attribute(attribute:"thorough_tests", value:"true");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Databases");

 script_dependencies("netbios_name_get.nasl",
                     "smb_login.nasl", "smb_registry_full_access.nasl",
		     "mssqlserver_detect.nasl", "smb_hotfixes.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login",
                     "SMB/password", "SMB/registry_full_access");
 script_require_ports(139, 445);

 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("byte_func.inc");
include("install_func.inc");
include("debug.inc");


function get_verbose_version(version)
{
  local_var v;
  version = split(version, sep:".", keep:FALSE);
  if (version[3])
    v = version[0] + '.' + version[1] + '.' + version[2] + '.' + version[3];
  if (!version[3])
    v = version[0] + '.' + version[1] + '.' + version[2];
  if (version[0] <= 7 && !isnull(version7[v]))
    return version7[v];
  else if(version[0] == 8 && !isnull(version8[v]))
    return version8[v];
  else if(version[0] == 9 && !isnull(version9[v]))
    return version9[v];
  else if (version[0] == 10)
  {
    if (version[1] == 50 && !isnull(version10_50[v]))
      return version10_50[v];
    else if (!isnull(version10[v]))
      return version10[v];
  }
  else if(version[0] == 11)
  {
    if (version[2] >= 9120 && !isnull(version12[v]))
      return version12[v];
    else if (!isnull(version11[v]))
      return version11[v];
  }
  else if(version[0] == 13)
  {
    if (version[2] >= 200 && !isnull(version16[v]))
      return version16[v];
    else if (!isnull(version12[v]))
      return version12[v];
  }
  else if (version[0] == 12 && !isnull(version12[v]))
    return version12[v];
  return NULL;
}

function retrieve_file_version(path)
{
  var fversion, ver, error;

  fversion = hotfix_get_fversion(path:path);
  error = hotfix_handle_error(error_code:fversion['error'], file:path);
  if(error) spad_log(message:error);

  if (!isnull(fversion.version))
    return fversion.version;

  return NULL;
}


function retrieve_files_info(&files_info, files)
{
  var file, ver;

  if (empty_or_null(files)) return NULL;

  foreach file (files)
  {
    if (!hotfix_file_exists(path:file)) return NULL;

    ver = retrieve_file_version(path:file);
    spad_log(message:'File: ' + file + '\nVersion: ' + ver);
    file = str_replace(string:file, find:"\\", replace:"\");
    if (!empty_or_null(ver))
      append_element(var:files_info, value:{'path': file, 'version': ver});
  }
}

function append_to_files_info_list(&files_info, version, path, arch)
{
  var osqlpath, sqlpath, files, bin, bins = [], program_files_dir;

  if (version =~ "^10\.0\.")
  {
    # Haven't found any SQL 2008 in the lab, and according to the pattern observed on other versions of SQL,
    # The digits in the path is likely to be '100' (100 probably represents 10.0, so 13.0 is 130, see examples in setup.exe)
    osqlpath = '\\Microsoft SQL Server\\100\\Tools\\Binn';
  }
  if (version =~ "^11\.0\.")
  {
    sqlpath = '\\Microsoft SQL Server\\110\\Setup Bootstrap\\SQLServer2012';
    osqlpath = '\\Microsoft SQL Server\\110\\Tools\\Binn';
  }
  else if (version =~ "^12\.0\.")
  {
    sqlpath = '\\Microsoft SQL Server\\120\\Setup Bootstrap\\SQLServer2014';
    osqlpath = '\\Microsoft SQL Server\\120\\Tools\\Binn';
  }
  else if (version =~ "^13\.0\.")
  {
    sqlpath = '\\Microsoft SQL Server\\130\\Setup Bootstrap\\SQLServer2016';
    osqlpath = '\\Microsoft SQL Server\\130\\Tools\\Binn';
  }
  else if (version =~ "^14\.0\.")
  {
    sqlpath = '\\Microsoft SQL Server\\140\\Setup Bootstrap\\SQL2017';
  }

  if (!empty_or_null(path))
    files = [hotfix_append_path(path:path, value:'sqlservr.exe')];

  if ( arch == 'x86' )
    program_files_dir = hotfix_get_programfilesdirx86();
  else if ( arch == 'x64' )
    program_files_dir = hotfix_get_programfilesdir();

  if (!empty_or_null(sqlpath))
    append_element(
      var:bins,
      value:hotfix_append_path(path:sqlpath, value:'setup.exe')
    );

  if (!empty_or_null(osqlpath))
  {
    foreach var f (['xmlrw.dll', 'OSQL.exe'])
    {
      append_element(
        var:bins,
        value:hotfix_append_path(path:osqlpath, value:f)
      );
    }
  }

  if (!empty_or_null(program_files_dir))
    foreach bin (bins)
      append_element(var:files, value:hotfix_append_path(path:program_files_dir, value:bin));

  spad_log(message:'Collecting info from the following files: ' + obj_rep(files));

  retrieve_files_info(files_info:files_info, files:files);
}


# versions culled from ;
# http://www.sqlsecurity.com
# http://sqlserverbuilds.blogspot.com
# https://sqlserverupdates.com/

# SQL 2022
var last_version22 = "16.0.1000.6";
var version22;

version22["16.0.1000.6"] = "2022 RTM";

# SQL 2019
var last_version19 = "15.0.4261.1";
var version19;

version19["15.0.4261.1"] = "2019 CU18 (KB5017593)";
version19["15.0.4249.2"] = "2019 CU17 (KB5016394)";
version19["15.0.4236.7"] = "2019 CU16 GDR (KB5014353)";
version19["15.0.2095.3"] = "2019 GDR (KB5014356)";
version19["15.0.4223.1"] = "2019 CU16 (KB5011644)";
version19["15.0.4198.2"] = "2019 CU15 (KB5008996)";
version19["15.0.4188.2"] = "2019 CU14 (KB5007182)";
version19["15.0.4178.1"] = "2019 CU13 (KB5005679)";
version19["15.0.4153.1"] = "2019 CU12 (KB5004524)";
version19["15.0.4138.2"] = "2019 CU11 (KB5003249)";
version19["15.0.4123.1"] = "2019 CU10 (KB5001090)";
version19["15.0.4102.2"] = "2019 CU9 (KB5000642)";
version19["15.0.4083.2"] = "2019 CU8 GDR (KB4583459)";
version19["15.0.2080.9"] = "2019 GDR (KB4583458)";
version19["15.0.4073.23"] = "2019 CU8 (KB4577194)";
version19["15.4063.15"] = "2019 CU7)"; # this CU was removed from production
version19["15.0.4053.23"] = "2019 CU6 (KB4563110)";
version19["15.0.4043.16"] = "2019 CU5 (KB4552255)";
version19["15.0.4033.1"] = "2019 CU4 (KB4548597)";
version19["15.0.4023.6"] = "2019 CU3 (KB4538853)";
version19["15.0.4013.40"] = "2019 CU2 (KB4536075)";
version19["15.0.4003.23"] = "2019 CU1 (KB4527376)";
version19["15.0.2070.41"] = "2019 GDR (KB4517790)";
version19["15.0.2000.5"] = "2019 RTM";

# SQL 2017
var last_version17 = "14.0.3456.2";
var version17;

version17["14.0.3456.2"] = "2017 CU31 (KB5016884)";
version17["14.0.3451.2"] = "2017 CU30 (KB5013756)";
version17["14.0.3445.2"] = "2017 GDR (KB5014553)";
version17["14.0.3436.1"] = "2017 CU29 (KB5010786)";
version17["14.0.3430.2"] = "2017 CU28 (KB5008084)";
version17["14.0.3421.10"] = "2017 CU27 (KB5006944)";
version17["14.0.3411.3"] = "2017 CU26 (KB5005226)";
version17["14.0.3401.7"] = "2017 CU25 (KB5003830)";
version17["14.0.3391.2"] = "2017 CU24 (KB5001228)";
version17["14.0.3381.3"] = "2017 CU23 (KB5000685)";
version17["14.0.3370.1"] = "2017 CU22 GDR (KB4583457)";
version17["14.0.3356.20"] = "2017 CU22 (KB4577467)";
version17["14.0.3335.7"] = "2017 CU21 (KB4557397)";
version17["14.0.3294.2"] = "2017 CU20 (KB4541283)";
version17["14.0.3281.6"] = "2017 CU19 (KB4535007)";
version17["14.0.3257.3"] = "2017 CU18 (KB4527377)";
version17["14.0.2042.3"] = "2017 RTM GDR (KB5014354)";
version17["14.0.1000.169"] = "2017 RTM";

# SQL 2016
var last_version16 = "13.0.6419.1";
var version16;

version16["13.0.6419.1"] = "2016 GDR (KB5014355)";
version16["13.0.6404.1"] = "2016 Hotfix (KB5006943)";
version16["13.0.6300.2"] = "2016 SP3 (KB5003279)";
version16["13.0.5108.50"] = "2016 SP2 GDR (KB5014365)";
version16["13.0.5026.0"] = "2016 SP2 (KB4052908)";
version16["13.0.4001.0"] = "2016 SP1 (KB3182545)";
version16["13.0.2149"] = "2016 + CU1 (KB3164674)";
version16["13.0.1708"] = "2016 + Critical update for SQL Server 2016 MSVCRT prerequisites (KB3164398)";
version16["13.0.1601"] = "2016";
version16["13.0.1400"] = "2016 Release Candidate 3";
version16["13.0.1300"] = "2016 Release Candidate 2";
version16["13.0.1200"] = "2016 Release Candidate 1";
version16["13.0.1100"] = "2016 Release Candidate 0";
version16["13.0.1000"] = "CTP3.3";
version16["13.0.900"] = "CTP3.2";
version16["13.0.800"] = "CTP3.1";
version16["13.0.700"] = "CTP3.0";
version16["13.0.600"] = "CTP2.4";
version16["13.0.500"] = "CTP2.3";
version16["13.0.407"] = "CTP2.2";
version16["13.0.300"] = "CTP2.1";
version16["13.0.200"] = "CTP2";

# SQL 2014
var last_version12 = "12.0.6439.10";
var version12;

version12["12.0.6439.10"] = "2014 + SP3 CU4 Security Update June 2022 (KB5014164)";
version12["12.0.6169.19"] = "2014 + SP3 GDR Security Update June 2022 (KB5014165)";
version12["12.0.6433.1"] = "2014 + SP3 CU4 Security Update January 2021 (KB4583462)";
version12["12.0.6024.0"] = "2014 + SP3 CU4 Security Update Febraury 2020 (KB4535288)";
version12["12.0.6329.1"] = "2014 + SP3 CU4 (KB4500181)";
version12["12.0.6024.0"] = "2014 + SP3 (KB4022619)";
version12["12.0.5000"] = "2014 + SP2 (KB3171021)";
version12["12.0.4459"] = "2014 + SP1 CU7 (KB3162659)";
version12["12.0.4457"] = "2014 + SP1 CU6 (KB3167392)";
version12["12.0.4439"] = "2014 + SP1 CU5 (KB3130926)";
version12["12.0.4436"] = "2014 + SP1 CU4 (KB3106660)";
version12["12.0.4427"] = "2014 + SP1 CU3 (KB3094221)";
version12["12.0.4422"] = "2014 + SP1 CU2 (KB3075950)";
version12["12.0.4416"] = "2014 + SP1 CU1 (KB3067839)";
version12["12.0.4213"] = "2014 + MS15-058 GDR Security Update (KB3070446)";
version12["12.0.4100"] = "2014 + SP1 (KB3058865)";
version12["12.0.2569"] = "2014 + Cumulative Update 14 (KB3158271)";
version12["12.0.2568"] = "2014 + Cumulative Update 13 (KB3144517)";
version12["12.0.2564"] = "2014 + Cumulative Update 12 (KB3130923)";
version12["12.0.2560"] = "2014 + Cumulative Update 11 (KB3106659)";
version12["12.0.2556"] = "2014 + Cumulative Update 10 (KB3094220)";
version12["12.0.2553"] = "2014 + Cumulative Update 9 (KB3075949)";
version12["12.0.2548"] = "2014 + MS15-058 Fix (QFE) (KB3045324)";
version12["12.0.2546"] = "2014 + Cumulative Update 8 (KB3067836)";
version12["12.0.2495"] = "2014 + Cumulative Update 7 (KB3046038)";
version12["12.0.2480"] = "2014 + Cumulative Update 6 (KB3031047)";
version12["12.0.2456"] = "2014 + Cumulative Update 5 (KB3011055)";
version12["12.0.2430"] = "2014 + Cumulative Update 4 (KB2999197)";
version12["12.0.2423"] = "2014 + RTDATA_LIST Wait Type Fix (KB3007050)";
version12["12.0.2405"] = "2014 + Table Joins Performance Fix (KB2999809)";
version12["12.0.2402"] = "2014 + Cumulative Update 3 (KB2984923)";
version12["12.0.2381"] = "2014 + MS14-044 Fix (QFE) (KB2977316)";
version12["12.0.2370"] = "2014 + Cumulative Update 2 (KB2967546)";
version12["12.0.2342"] = "2014 + Cumulative Update 1 (KB2931693)";
version12["12.0.2269"] = "2014 + MS15-058 Fix (GDR) (KB3045323)";
version12["12.0.2254"] = "2014 + MS14-044 Fix (GDR) (KB2977315)";
version12["12.0.2000"] = "2014";
version12["12.0.1524"] = "2014 CTP2";
version12["11.0.9120"] = "2014 CTP1";


# SQL 2012 

var last_version11 = "11.0.7507.2";
var version11;

version11["11.0.9000"] = "2012 with Power View For Multidimensional Models CTP3";
version11["11.0.7507.2"] = "2012 SP4 + Cumulative Update January 2021 (KB4583465)";
version11["11.0.7493.4"] = "2012 SP4 + Cumulative Update Febraury 2020 (KB4532098)";
version11["11.0.7462.6"] = "2012 SP4 + Cumulative Update January 2018 (KB4057116)";
version11["11.0.7001"] = "2012 SP4 (KB4018073)";
version11["11.0.6607.3"] = "2012 SP3 + Cumulative Update 10 (KB4025925)";
version11["11.0.6598"] = "2012 SP3 + Cumulative Update 9 (KB4016762)";
version11["11.0.6594"] = "2012 SP3 + Cumulative Update 8 (KB4013104)";
version11["11.0.6579"] = "2012 SP3 + Cumulative Update 7 (KB3205051)";
version11["11.0.6567"] = "2012 SP3 + Cumulative Update 6 (KB3194992)";
version11["11.0.6544"] = "2012 SP3 + Cumulative Update 5 (KB3180915)";
version11["11.0.6540"] = "2012 SP3 + Cumulative Update 4 (KB3165264)";
version11["11.0.6537"] = "2012 SP3 + Cumulative Update 3 (KB3152635)";
version11["11.0.6523"] = "2012 SP3 + Cumulative Update 2 (KB3137746)";
version11["11.0.6518"] = "2012 SP3 + Cumulative Update 1 (KB3123299)";
version11["11.0.6020"] = "2012 SP3 RTW/PCU 3 (KB3072779)";
version11["11.0.5655"] = "2012 SP2 + Cumulative Update 13 (KB3165266)";
version11["11.0.5649"] = "2012 SP2 + Cumulative Update 12 (KB3152637)";
version11["11.0.5646"] = "2012 SP2 + Cumulative Update 11 (KB3137745)";
version11["11.0.5644"] = "2012 SP2 + Cumulative Update 10 (KB3120313)";
version11["11.0.5641"] = "2012 SP2 + Cumulative Update 9 (KB3098512)";
version11["11.0.5634"] = "2012 SP2 + Cumulative Update 8 (KB3082561)";
version11["11.0.5623"] = "2012 SP2 + Cumulative Update 7 (KB3072100)";
version11["11.0.5613"] = "2012 SP2 + MS15-058 Fix (QFE) (KB3045319)";
version11["11.0.5592"] = "2012 SP2 + Cumulative Update 6 (KB3052468)";
version11["11.0.5582"] = "2012 SP2 + Cumulative Update 5 (KB3037255)";
version11["11.0.5569"] = "2012 SP2 + Cumulative Update 4 (KB3007556)";
version11["11.0.5556"] = "2012 SP2 + Cumulative Update 3 (KB3002049)";
version11["11.0.5548"] = "2012 SP2 + Cumulative Update 2 (KB2983175)";
version11["11.0.5532"] = "2012 SP2 + Cumulative Update 1 (KB2976982)";
version11["11.0.5343"] = "2012 SP2 + MS15-058 Fix (GDR) (KB3045321)";
version11["11.0.5058"] = "2012 SP2";
version11["11.0.3513"] = "2012 SP1 + MS15-058 Fix (QFE) (KB3045317)";
version11["11.0.3482"] = "2012 SP1 + Cumulative Update 13 (KB3002044)";
version11["11.0.3470"] = "2012 SP1 + Cumulative Update 12 (KB2991533)";
version11["11.0.3460"] = "2012 SP1 + MS14-044 Fix (QFE) (KB2977325)";
version11["11.0.3449"] = "2012 SP1 + Cumulative Update 11 (KB2975396)";
version11["11.0.3437"] = "2012 SP1 + Cumulative Update 10 + Clustered Index Data Loss Fix (KB2969896)";
version11["11.0.3431"] = "2012 SP1 + Cumulative Update 10 (KB2954099)";
version11["11.0.3412"] = "2012 SP1 + Cumulative Update 9 (KB2931078)";
version11["11.0.3401"] = "2012 SP1 + Cumulative Update 8 (KB2917531)";
version11["11.0.3393"] = "2012 SP1 + Cumulative Update 7 (KB2894115)";
version11["11.0.3381"] = "2012 SP1 + Cumulative Update 6 (KB2874879)";
version11["11.0.3373"] = "2012 SP1 + Cumulative Update 5 (KB2861107)";
version11["11.0.3368"] = "2012 SP1 + Cumulative Update 4 (KB2833645)";
version11["11.0.3350"] = "2012 SP1 + Cumulative Update 3 + SSIS Fix (KB2832017)";
version11["11.0.3349"] = "2012 SP1 + Cumulative Update 3 (KB2812412)";
version11["11.0.3339"] = "2012 SP1 + Cumulative Update 2 (KB2790947)";
version11["11.0.3335"] = "2012 SP1 + Component Installation Process Fix (KB2800050)";
version11["11.0.3321"] = "2012 SP1 + Cumulative Update 1 (KB2765331)";
version11["11.0.3156"] = "2012 SP1 + MS15-058 Fix (GDR) (KB3045318)";
version11["11.0.3153"] = "2012 SP1 + MS14-044 Fix (GDR) (KB2977326)";
version11["11.0.3128"] = "2012 SP1 + Installer Repeated Start Fix (KB2793634)";
version11["11.0.3000"] = "2012 SP1";
version11["11.0.2845"] = "2012 SP1 CTP";
version11["11.0.2424"] = "2012 + Cumulative Update 11 (KB2908007)";
version11["11.0.2420"] = "2012 + Cumulative Update 10 (KB2891666)";
version11["11.0.2419"] = "2012 + Cumulative Update 9 (KB2867319)";
version11["11.0.2410"] = "2012 + Cumulative Update 8 (KB2844205)";
version11["11.0.2405"] = "2012 + Cumulative Update 7 (KB2823247)";
version11["11.0.2401"] = "2012 + Cumulative Update 6 (KB2728897)";
version11["11.0.2395"] = "2012 + Cumulative Update 5 (KB2777772)";
version11["11.0.2383"] = "2012 + Cumulative Update 4 (KB2758687)";
version11["11.0.2376"] = "2012 + MS12-070 Fix (QFE) (KB2716441)";
version11["11.0.2332"] = "2012 + Cumulative Update 3 (KB2723749)";
version11["11.0.2325"] = "2012 + Cumulative Update 2 (KB2703275)";
version11["11.0.2318"] = "2012 + MS12-070 Fix (KB2716442)";
version11["11.0.2316"] = "2012 + Cumulative Update 1 (KB2679368)";
version11["11.0.2214"] = "2012 + SSAS Fix (KB2685308)";
version11["11.0.2100"] = "2012";
version11["11.0.1913"] = "2012 Release Candidate 1";
version11["11.0.1750"] = "2012 Release Candidate 0";
version11["11.0.1440"] = "2012 CTP3";
version11["11.0.1103"] = "2012 CTP1";

# SQL 2008 R2

var last_version10_50 = "10.50.6560";
var version10_50;

version10_50["10.50.6560"] = "2008 R2 SP3 Meltdown/Spectre GDR (KB4057113)";
version10_50["10.50.6529"] = "2008 R2 SP3 + MS15-058 Fix (QFE) (KB3045314)";
version10_50["10.50.6220"] = "2008 R2 SP3 + MS15-058 Fix (GDR) (KB3045316)";
version10_50["10.50.6000"] = "2008 R2 SP3";
version10_50["10.50.4339"] = "2008 R2 SP2 + MS15-058 Fix (QFE) (KB3045312)";
version10_50["10.50.4331"] = "2008 R2 SP2 + MS14-044 Fix (QFE) + 9004 Error Fix (KB2987585)";
version10_50["10.50.4321"] = "2008 R2 SP2 + MS14-044 Fix (QFE) (KB2977319)";
version10_50["10.50.4319"] = "2008 R2 SP2 + Cumulative Update 13 (KB2967540)";
version10_50["10.50.4305"] = "2008 R2 SP2 + Cumulative Update 12 (KB2938478)";
version10_50["10.50.4302"] = "2008 R2 SP2 + Cumulative Update 11 (KB2926028)";
version10_50["10.50.4297"] = "2008 R2 SP2 + Cumulative Update 10 (KB2908087)";
version10_50["10.50.4295"] = "2008 R2 SP2 + Cumulative Update 9 (KB2887606)";
version10_50["10.50.4290"] = "2008 R2 SP2 + Cumulative Update 8 (KB2871401)";
version10_50["10.50.4286"] = "2008 R2 SP2 + Cumulative Update 7 (KB2844090)";
version10_50["10.50.4285"] = "2008 R2 SP2 + Cumulative Update 6 (updated) (KB2830140)";
version10_50["10.50.4279"] = "2008 R2 SP2 + Cumulative Update 6 (replaced) (KB2830140)";
version10_50["10.50.4276"] = "2008 R2 SP2 + Cumulative Update 5 (KB2797460)";
version10_50["10.50.4270"] = "2008 R2 SP2 + Cumulative Update 4 (KB2777358)";
version10_50["10.50.4266"] = "2008 R2 SP2 + Cumulative Update 3 (KB2754552)";
version10_50["10.50.4263"] = "2008 R2 SP2 + Cumulative Update 2 (KB2740411)";
version10_50["10.50.4260"] = "2008 R2 SP2 + Cumulative Update 1 (KB2720425)";
version10_50["10.50.4042"] = "2008 R2 SP2 + MS15-058 Fix (GDR) (KB3045313)";
version10_50["10.50.4033"] = "2008 R2 SP2 + MS14-044 Fix (GDR) (KB2977320)";
version10_50["10.50.4000"] = "2008 R2 SP2";
version10_50["10.50.3720"] = "2008 R2 SP2 CTP";
version10_50["10.50.2881"] = "2008 R2 SP1 + Cumulative Update 13 + On-Demand Hotfix (KB2868244)";
version10_50["10.50.2876"] = "2008 R2 SP1 + Cumulative Update 13 (KB2855792)";
version10_50["10.50.2875"] = "2008 R2 SP1 + Cumulative Update 12 (updated) (KB2828727)";
version10_50["10.50.2874"] = "2008 R2 SP1 + Cumulative Update 12 (replaced) (KB2828727)";
version10_50["10.50.2869"] = "2008 R2 SP1 + Cumulative Update 11 (KB2812683)";
version10_50["10.50.2868"] = "2008 R2 SP1 + Cumulative Update 10 (KB2783135)";
version10_50["10.50.2866"] = "2008 R2 SP1 + Cumulative Update 9 (KB2756574)";
version10_50["10.50.2861"] = "2008 R2 SP1 + MS12-070 Fix (QFE) (KB2716439)";
version10_50["10.50.2822"] = "2008 R2 SP1 + Cumulative Update 8 (KB2723743)";
version10_50["10.50.2817"] = "2008 R2 SP1 + Cumulative Update 7 (KB2703282)";
version10_50["10.50.2811"] = "2008 R2 SP1 + Cumulative Update 6 (KB2679367)";
version10_50["10.50.2807"] = "2008 R2 SP1 + Cumulative Update 5 + DML Statement Fix (KB2675522)";
version10_50["10.50.2806"] = "2008 R2 SP1 + Cumulative Update 5 (KB2659694)";
version10_50["10.50.2799"] = "2008 R2 SP1 + Cumulative Update 4 + Non-yielding Scheduler Error Fix (KB2633357)";
version10_50["10.50.2796"] = "2008 R2 SP1 + Cumulative Update 4 (KB2633146)";
version10_50["10.50.2789"] = "2008 R2 SP1 + Cumulative Update 3 (KB2591748)";
version10_50["10.50.2776"] = "2008 R2 SP1 + Cumulative Update 2 + Slow Performance Fix (KB2606883)";
version10_50["10.50.2772"] = "2008 R2 SP1 + Cumulative Update 2 (KB2567714)";
version10_50["10.50.2769"] = "2008 R2 SP1 + Cumulative Update 1 (KB2544793)";
version10_50["10.50.2550"] = "2008 R2 SP1 + MS12-070 Fix (KB2716440)";
version10_50["10.50.2500"] = "2008 R2 SP1";
version10_50["10.50.1817"] = "2008 R2 + Cumulative Update 14 (KB2703280)";
version10_50["10.50.1815"] = "2008 R2 + Cumulative Update 13 (KB2679366)";
version10_50["10.50.1810"] = "2008 R2 + Cumulative Update 12 (KB2659692)";
version10_50["10.50.1809"] = "2008 R2 + Cumulative Update 11 (KB2633145)";
version10_50["10.50.1807"] = "2008 R2 + Cumulative Update 10 (KB2591746)";
version10_50["10.50.1804"] = "2008 R2 + Cumulative Update 9 (KB2567713)";
version10_50["10.50.1800"] = "2008 R2 + Cumulative Update 8 + Sparse Database Data Files Fix (KB2574699)";
version10_50["10.50.1797"] = "2008 R2 + Cumulative Update 8 (KB2534352)";
version10_50["10.50.1790"] = "2008 R2 + Cumulative Update 8 + MS11-049 Fix (KB2494086)";
version10_50["10.50.1777"] = "2008 R2 + Cumulative Update 7 (KB2507770)";
version10_50["10.50.1769"] = "2008 R2 + Cumulative Update 6 + Non-yielding Scheduler Error Fix (KB2520808)";
version10_50["10.50.1765"] = "2008 R2 + Cumulative Update 6 (KB2489376)";
version10_50["10.50.1753"] = "2008 R2 + Cumulative Update 5 (KB2438347)";
version10_50["10.50.1746"] = "2008 R2 + Cumulative Update 4 (KB2345451)";
version10_50["10.50.1734"] = "2008 R2 + Cumulative Update 3 (KB2261464)";
version10_50["10.50.1720"] = "2008 R2 + Cumulative Update 2 (KB2072493)";
version10_50["10.50.1702"] = "2008 R2 + Cumulative Update 1 (Q981355)";
version10_50["10.50.1617"] = "2008 R2 + MS11-049 Fix (KB2494088)";
version10_50["10.50.1600"] = "2008 R2";

# SQL 2008

var last_version10 = "10.0.6556";
var version10;

version10["10.0.6556"] = "2008 SP4 Meltdown/Spectre GDR (KB4057114)";
version10["10.0.6535"] = "2008 SP4 + MS15-058 Fix (QFE) (KB3045308)";
version10["10.0.6241"] = "2008 SP4 + MS15-058 Fix (GDR) (KB3045311)";
version10["10.0.6000"] = "2008 SP4";
version10["10.0.5890"] = "2008 SP3 + MS15-058 Fix (QFE) (KB3045303)";
version10["10.0.5869"] = "2008 SP3 + MS14-044 Fix (QFE) (KB2977322)";
version10["10.0.5867"] = "2008 SP3 + dbcc shrinkfile Statement Error 8985 Fix (KB2877204)";
version10["10.0.5861"] = "2008 SP3 + Cumulative Update 17 (KB2958696)";
version10["10.0.5852"] = "2008 SP3 + Cumulative Update 16 (KB2936421)";
version10["10.0.5850"] = "2008 SP3 + Cumulative Update 15 (KB2923520)";
version10["10.0.5848"] = "2008 SP3 + Cumulative Update 14 (KB2893410)";
version10["10.0.5846"] = "2008 SP3 + Cumulative Update 13 (KB2880350)";
version10["10.0.5844"] = "2008 SP3 + Cumulative Update 12 (KB2863205)";
version10["10.0.5841"] = "2008 SP3 + Cumulative Update 11 (updated) (KB2834048)";
version10["10.0.5840"] = "2008 SP3 + Cumulative Update 11 (replaced) (KB2834048)";
version10["10.0.5835"] = "2008 SP3 + Cumulative Update 10 (KB2814783)";
version10["10.0.5829"] = "2008 SP3 + Cumulative Update 9 (KB2799883)";
version10["10.0.5828"] = "2008 SP3 + Cumulative Update 8 (KB2771833)";
version10["10.0.5826"] = "2008 SP3 + MS12-070 Fix (QFE) (KB2716435)";
version10["10.0.5794"] = "2008 SP3 + Cumulative Update 7 (KB2738350)";
version10["10.0.5788"] = "2008 SP3 + Cumulative Update 6 (KB2715953)";
version10["10.0.5785"] = "2008 SP3 + Cumulative Update 5 (KB2696626)";
version10["10.0.5775"] = "2008 SP3 + Cumulative Update 4 (KB2673383)";
version10["10.0.5770"] = "2008 SP3 + Cumulative Update 3 (KB2648098)";
version10["10.0.5768"] = "2008 SP3 + Cumulative Update 2 (KB2633143)";
version10["10.0.5766"] = "2008 SP3 + Cumulative Update 1 (KB2617146)";
version10["10.0.5538"] = "2008 SP3 + MS15-058 Fix (GDR) (KB3045305)";
version10["10.0.5520"] = "2008 SP3 + MS14-044 Fix (GDR) (KB2977321)";
version10["10.0.5512"] = "2008 SP3 + MS12-070 Fix (KB2716436)";
version10["10.0.5500"] = "2008 SP3";
version10["10.0.5416"] = "2008 SP3 CTP";
version10["10.0.2531"] = "2008 SP2 + MS12-070 Fix (QFE) (KB2716433)";
version10["10.0.4333"] = "2008 SP2 + Cumulative Update 11 (KB2715951)";
version10["10.0.4332"] = "2008 SP2 + Cumulative Update 10 (KB2696625)";
version10["10.0.4330"] = "2008 SP2 + Cumulative Update 9 (KB2673382)";
version10["10.0.4326"] = "2008 SP2 + Cumulative Update 8 (KB2648096)";
version10["10.0.4323"] = "2008 SP2 + Cumulative Update 7 (KB2617148)";
version10["10.0.4321"] = "2008 SP2 + Cumulative Update 6 (KB2582285)";
version10["10.0.4316"] = "2008 SP2 + Cumulative Update 5 (KB2555408)";
version10["10.0.4285"] = "2008 SP2 + Cumulative Update 4 (KB2527180)";
version10["10.0.4279"] = "2008 SP2 + Cumulative Update 3 (KB2498535)";
version10["10.0.4272"] = "2008 SP2 + Cumulative Update 2 (KB2467239)";
version10["10.0.4266"] = "2008 SP2 + Cumulative Update 1 (KB2289254)";
version10["10.0.4067"] = "2008 SP2 + MS12-070 Fix (KB2716434)";
version10["10.0.4064"] = "2008 SP2 + MS11-049 Fix (KB2494089)";
version10["10.0.4000"] = "2008 SP2";
version10["10.0.3798"] = "2008 SP2 CTP";
version10["10.0.2850"] = "2008 SP1 + Cumulative Update 16 (KB2582282)";
version10["10.0.2847"] = "2008 SP1 + Cumulative Update 15 (KB2555406)";
version10["10.0.2821"] = "2008 SP1 + Cumulative Update 14 (KB2527187)";
version10["10.0.2816"] = "2008 SP1 + Cumulative Update 13 (KB2497673)";
version10["10.0.2808"] = "2008 SP1 + Cumulative Update 12 (KB2467236)";
version10["10.0.2804"] = "2008 SP1 + Cumulative Update 11 (KB2413738)";
version10["10.0.2799"] = "2008 SP1 + Cumulative Update 10 (KB2279604)";
version10["10.0.2789"] = "2008 SP1 + Cumulative Update 9 (KB2083921)";
version10["10.0.2787"] = "2008 SP1 + Fixed Cumulative Update 7 or 8 (KB2231277)";
version10["10.0.2775"] = "2008 SP1 + Cumulative Update 8 (Q981702)";
version10["10.0.2766"] = "2008 SP1 + Cumulative Update 7 (Q979065)";
version10["10.0.2757"] = "2008 SP1 + Cumulative Update 6 (Q977443)";
version10["10.0.2746"] = "2008 SP1 + Cumulative Update 5 (Q975977)";
version10["10.0.2740"] = "2008 SP1 + Fixed Cumulative Update 3 or 4 (Q976761)";
version10["10.0.2734"] = "2008 SP1 + Cumulative Update 4 (Q973602)";
version10["10.0.2723"] = "2008 SP1 + Cumulative Update 3 (Q971491)";
version10["10.0.2714"] = "2008 SP1 + Cumulative Update 2 (Q970315)";
version10["10.0.2712"] = "2008 SP1 + Q970507";
version10["10.0.2710"] = "2008 SP1 + Cumulative Update 1 (Q969099)";
version10["10.0.2573"] = "2008 SP1 + MS11-049 Fix (KB2494096)";
version10["10.0.2531"] = "2008 SP1";
version10["10.0.2520"] = "2008 SP1 CTP";
version10["10.0.1835"] = "2008 + Cumulative Update 10 (Q979064)";
version10["10.0.1828"] = "2008 + Cumulative Update 9 (Q977444)";
version10["10.0.1823"] = "2008 + Cumulative Update 8 (Q975976)";
version10["10.0.1818"] = "2008 + Cumulative Update 7 (Q973601)";
version10["10.0.1812"] = "2008 + Cumulative Update 6 (Q971490)";
version10["10.0.1806"] = "2008 + Cumulative Update 5 (Q969531)";
version10["10.0.1798"] = "2008 + Cumulative Update 4 (Q963036)";
version10["10.0.1787"] = "2008 + Cumulative Update 3 (Q960484)";
version10["10.0.1779"] = "2008 + Cumulative Update 2 (Q958186)";
version10["10.0.1771"] = "2008 + Q958611";
version10["10.0.1763"] = "2008 + Cumulative Update 1 (Q956717)";
version10["10.0.1750"] = "2008 + Q956718";
version10["10.0.1600"] = "2008";

# SQL 2005

var last_version9 = "9.00.5324";
var version9;

version9["9.00.5324"] = "2005 SP4 + MS12-070 Fix (QFE) (KB 2716427)";
version9["9.00.5296"] = "2005 SP4 + Cumulative Update 3 + Msg 7359 Fix (KB 2615425)";
version9["9.00.5295"] = "2005 SP4 + Cumulative Update 3 + Agent Job Stop Fix (KB 2598903)";
version9["9.00.5294"] = "2005 SP4 + Cumulative Update 3 + Error 5180 Fix (KB 2572407)";
version9["9.00.5292"] = "2005 SP4 + Cumulative Update 3 + MS11-049 Fix (KB 2494123)";
version9["9.00.5266"] = "2005 SP4 + Cumulative Update 3 (KB 2507769)";
version9["9.00.5259"] = "2005 SP4 + Cumulative Update 2 (KB 2489409)";
version9["9.00.5254"] = "2005 SP4 + Cumulative Update 1 (KB 2464079)";
version9["9.00.5069"] = "2005 SP4 + MS12-070 Fix (KB 2716429)";
version9["9.00.5057"] = "2005 SP4 + MS11-049 Fix (KB 2494120)";
version9["9.00.5000"] = "2005 SP4 (KB 2463332)";
version9["9.00.4912"] = "2005 SP4 CTP";
version9["9.00.4340"] = "2005 SP3 + Cumulative Update 15 + MS11-049 Fix (KB 2494112)";
version9["9.00.4325"] = "2005 SP3 + Cumulative Update 15 (KB 2507766)";
version9["9.00.4317"] = "2005 SP3 + Cumulative Update 14 (KB 2489375)";
version9["9.00.4315"] = "2005 SP3 + Cumulative Update 13 (KB 2438344)";
version9["9.00.4311"] = "2005 SP3 + Cumulative Update 12 (KB 2345449)";
version9["9.00.4309"] = "2005 SP3 + Cumulative Update 11 (KB 2258854)";
version9["9.00.4305"] = "2005 SP3 + Cumulative Update 10 (Q983329)";
version9["9.00.4294"] = "2005 SP3 + Cumulative Update 9 (Q980176)";
version9["9.00.4285"] = "2005 SP3 + Cumulative Update 8 (Q978915)";
version9["9.00.4273"] = "2005 SP3 + Cumulative Update 7 (Q976951)";
version9["9.00.4268"] = "2005 SP3 + Q977151";
version9["9.00.4266"] = "2005 SP3 + Cumulative Update 6 (Q974648)";
version9["9.00.4262"] = "2005 SP3 + Cumulative Update 6 (QFE) (Q970894)";
version9["9.00.4230"] = "2005 SP3 + Cumulative Update 5 (Q972511)";
version9["9.00.4226"] = "2005 SP3 + Cumulative Update 4 (Q970279)";
version9["9.00.4224"] = "2005 SP3 + Q971409";
version9["9.00.4220"] = "2005 SP3 + Cumulative Update 3 (Q967909)";
version9["9.00.4216"] = "2005 SP3 + Q967101";
version9["9.00.4211"] = "2005 SP3 + Cumulative Update 2 (Q961930)";
version9["9.00.4207"] = "2005 SP3 + Cumulative Update 1 (Q959195)";
version9["9.00.4060"] = "2005 SP3 + MS11-049 Fix (KB 2494113)";
version9["9.00.4053"] = "2005 SP3 + MS09-062 Fix (Q970892)";
version9["9.00.4035"] = "2005 SP3 (Q955706)";
version9["9.00.3356"] = "2005 SP2 + Cumulative Update 17 (Q976952)";
version9["9.00.3355"] = "2005 SP2 + Cumulative Update 16 (Q974647)";
version9["9.00.3353"] = "2005 SP2 + Cumulative Update 15 + MS09-062 Fix (Q970896)";
version9["9.00.3330"] = "2005 SP2 + Cumulative Update 15 (Q972510)";
version9["9.00.3328"] = "2005 SP2 + Cumulative Update 14 (Q970278)";
version9["9.00.3327"] = "2005 SP2 + Cumulative Update 17 + LOB Fix (Q948567 / 961648)";
version9["9.00.3325"] = "2005 SP2 + Cumulative Update 13 (Q967908)";
version9["9.00.3320"] = "2005 SP2 + Q969142";
version9["9.00.3318"] = "2005 SP2 + Q967199";
version9["9.00.3315"] = "2005 SP2 + Cumulative Update 12 (Q962970)";
version9["9.00.3310"] = "2005 SP2 + Q960090";
version9["9.00.3303"] = "2005 SP2 + Q962209";
version9["9.00.3302"] = "2005 SP2 + Q961479 / 961648";
version9["9.00.3301"] = "2005 SP2 + Cumulative Update 11 (Q958735)";
version9["9.00.3295"] = "2005 SP2 + Q959132";
version9["9.00.3294"] = "2005 SP2 + Cumulative Update 10 (Q956854)";
version9["9.00.3291"] = "2005 SP2 + Q956889";
version9["9.00.3289"] = "2005 SP2 + Q937137";
version9["9.00.3282"] = "2005 SP2 + Cumulative Update 9 (Q953752 / 953607)";
version9["9.00.3261"] = "2005 SP2 + Q955754";
version9["9.00.3260"] = "2005 SP2 + Q954950";
version9["9.00.3259"] = "2005 SP2 + Q954669 / 954831";
version9["9.00.3257"] = "2005 SP2 + Cumulative Update 8 (Q951217)";
version9["9.00.3253"] = "2005 SP2 + Q954054";
version9["9.00.3244"] = "2005 SP2 + Q952330";
version9["9.00.3242"] = "2005 SP2 + Q951190";
version9["9.00.3240"] = "2005 SP2 + Q951204";
version9["9.00.3239"] = "2005 SP2 + Cumulative Update 7 (Q949095)";
version9["9.00.3235"] = "2005 SP2 + Q950189";
version9["9.00.3233"] = "2005 SP2 + Q941203 / 948108 (QFE)";
version9["9.00.3232"] = "2005 SP2 + Q949959";
version9["9.00.3231"] = "2005 SP2 + Q949687 / 949595";
version9["9.00.3230"] = "2005 SP2 + Q949199";
version9["9.00.3228"] = "2005 SP2 + Cumulative Update 6 (Q946608)";
version9["9.00.3224"] = "2005 SP2 + Q947463";
version9["9.00.3222"] = "2005 SP2 + Q945640 / 945641 / 947196 / 947197";
version9["9.00.3221"] = "2005 SP2 + Q942908 / 945442 / 945443 / 945916 / 944358 ";
version9["9.00.3215"] = "2005 SP2 + Cumulative Update 5 (Q941450)";
version9["9.00.3209"] = "2005 SP2 + KB N/A";
version9["9.00.3208"] = "2005 SP2 + Q944902";
version9["9.00.3206"] = "2005 SP2 + Q944677";
version9["9.00.3205"] = "2005 SP2 + KB N/A";
version9["9.00.3203"] = "2005 SP2 + KB N/A";
version9["9.00.3200"] = "2005 SP2 + Cumulative Update 4 (Q941450)";
version9["9.00.3195"] = "2005 SP2 + KB N/A";
version9["9.00.3194"] = "2005 SP2 + Q940933";
version9["9.00.3186"] = "2005 SP2 + Cumulative Update 3 (Q939562)";
version9["9.00.3182"] = "2005 SP2 + Q940128";
version9["9.00.3180"] = "2005 SP2 + Q939942";
version9["9.00.3179"] = "2005 SP2 + Q938243";
version9["9.00.3178"] = "2005 SP2 + KB N/A";
version9["9.00.3177"] = "2005 SP2 + Q939563 / 939285";
version9["9.00.3175"] = "2005 SP2 + Cumulative Update 2 (Q936305 / 938825)";
version9["9.00.3171"] = "2005 SP2 + Q937745";
version9["9.00.3169"] = "2005 SP2 + Q937041 / 937033";
version9["9.00.3166"] = "2005 SP2 + Q936185 / 934734";
version9["9.00.3162"] = "2005 SP2 + Q932610 / 935360 / 935922";
version9["9.00.3161"] = "2005 SP2 + Q935356 / 933724 (Cumulative HF1)";
version9["9.00.3159"] = "2005 SP2 + Q934459";
version9["9.00.3156"] = "2005 SP2 + Q934226";
version9["9.00.3155"] = "2005 SP2 + Q933549 / 933766 / 933808 / 933724 / 932115 / 933499";
version9["9.00.3154"] = "2005 SP2 + Q934106 / 934109 / 934188";
version9["9.00.3153"] = "2005 SP2 + Q933564";
version9["9.00.3152"] = "2005 SP2 + Cumulative Update 1 (Q933097)";
version9["9.00.3080"] = "2005 SP2 + MS09-062 Fix (Q970895)";
version9["9.00.3077"] = "2005 SP2 + MS09-004 Fix (Q960089)";
version9["9.00.3073"] = "2005 SP2 + MS08-052 Fix (Q954606)";
version9["9.00.3068"] = "2005 SP2 + Q941203 / 948109";
version9["9.00.3054"] = "2005 SP2 + Q934458";
version9["9.00.3050"] = "2005 SP2 + Q933508";
version9["9.00.3043"] = "2005 SP2 + Q933508";
version9["9.00.3042"] = "2005 SP2 'Fixed'";
version9["9.00.3033"] = "2005 SP2 CTP (December)";
version9["9.00.3027"] = "2005 SP2 CTP (November)";
version9["9.00.3026"] = "2005 SP1 + Q929376";
version9["9.00.2249"] = "2005 SP1 + Q948344";
version9["9.00.2245"] = "2005 SP1 + Q933573";
version9["9.00.2243"] = "2005 SP1 + Q944968";
version9["9.00.2242"] = "2005 SP1 + Q943389 / 943388";
version9["9.00.2239"] = "2005 SP1 + Q940961";
version9["9.00.2237"] = "2005 SP1 + Q940719";
version9["9.00.2236"] = "2005 SP1 + Q940287 / 940286";
version9["9.00.2234"] = "2005 SP1 + Q937343";
version9["9.00.2233"] = "2005 SP1 + Q933499 / 937545";
version9["9.00.2232"] = "2005 SP1 + Q937277";
version9["9.00.2231"] = "2005 SP1 + Q934812";
version9["9.00.2230"] = "2005 SP1 + Q936179";
version9["9.00.2229"] = "2005 SP1 + Q935446";
version9["9.00.2227"] = "2005 SP1 + Q934066 / 933265";
version9["9.00.2226"] = "2005 SP1 + Q933762 / 934065 / 934065";
version9["9.00.2224"] = "2005 SP1 + Q932990 / 933519";
version9["9.00.2223"] = "2005 SP1 + Q932393";
version9["9.00.2221"] = "2005 SP1 + Q931593";
version9["9.00.2219"] = "2005 SP1 + Q931329 / 932115";
version9["9.00.2218"] = "2005 SP1 + Q931843 / 931843";
version9["9.00.2216"] = "2005 SP1 + Q931821";
version9["9.00.2215"] = "2005 SP1 + Q931666";
version9["9.00.2214"] = "2005 SP1 + Q929240 / 930505 / 930775";
version9["9.00.2211"] = "2005 SP1 + Q930283 / 930284";
version9["9.00.2209"] = "2005 SP1 + Q929278";
version9["9.00.2208"] = "2005 SP1 + Q929179 / 929404";
version9["9.00.2207"] = "2005 SP1 + Q928394 / 928372 / 928789";
version9["9.00.2206"] = "2005 SP1 + Q928539 / 928083 / 928537";
version9["9.00.2202"] = "2005 SP1 + Q927643";
version9["9.00.2201"] = "2005 SP1 + Q927289";
version9["9.00.2198"] = "2005 SP1 + Q926773 / 926611 / 924808 / 925277 / 926612 / 924807 / 924686";
version9["9.00.2196"] = "2005 SP1 + Q926285 / 926335 / 926024";
version9["9.00.2195"] = "2005 SP1 + Q926240";
version9["9.00.2194"] = "2005 SP1 + Q925744";
version9["9.00.2192"] = "2005 SP1 + Q924954 / 925335";
version9["9.00.2191"] = "2005 SP1 + Q925135";
version9["9.00.2190"] = "2005 SP1 + Q925227";
version9["9.00.2189"] = "2005 SP1 + Q925153";
version9["9.00.2187"] = "2005 SP1 + Q923849";
version9["9.00.2183"] = "2005 SP1 + Q929404 / 924291";
version9["9.00.2181"] = "2005 SP1 + Q923624 / 923605";
version9["9.00.2176"] = "2005 SP1 + Q923296 / 922594";
version9["9.00.2175"] = "2005 SP1 + Q922578 / 922438 / 921536 / 922579 / 920794";
version9["9.00.2174"] = "2005 SP1 + Q922063";
version9["9.00.2167"] = "2005 SP1 + Q920974 / 921295";
version9["9.00.2164"] = "2005 SP1 + Q919636 / 918832 / 919775";
version9["9.00.2156"] = "2005 SP1 + Q919611";
version9["9.00.2153"] = "2005 SP1 + builds 1531-40";
version9["9.00.2050"] = "2005 SP1 + .NET Vulnerability fix";
version9["9.00.2047"] = "2005 SP1";
version9["9.00.2040"] = "2005 SP1 CTP";
version9["9.00.2029"] = "2005 SP1 Beta";
version9["9.00.1561"] = "2005 + Q932556";
version9["9.00.1558"] = "2005 + Q926493";
version9["9.00.1554"] = "2005 + Q926292";
version9["9.00.1551"] = "2005 + Q922804";
version9["9.00.1550"] = "2005 + Q917887 / 921106";
version9["9.00.1547"] = "2005 + Q918276";
version9["9.00.1545"] = "2005 + Q917905 / 919193";
version9["9.00.1541"] = "2005 + Q917888 / 917971";
version9["9.00.1539"] = "2005 + Q917738";
version9["9.00.1538"] = "2005 + Q917824";
version9["9.00.1536"] = "2005 + Q917016";
version9["9.00.1534"] = "2005 + Q916706";
version9["9.00.1533"] = "2005 + Q916086";
version9["9.00.1532"] = "2005 + Q916046";
version9["9.00.1531"] = "2005 + Q915918";
version9["9.00.1528"] = "2005 + Q915112 / 915306 / 915307/ 915308";
version9["9.00.1519"] = "2005 + Q913494";
version9["9.00.1518"] = "2005 + Q912472 / 913371 / 913941";
version9["9.00.1514"] = "2005 + Q912471";
version9["9.00.1503"] = "2005 + Q911662";
version9["9.00.1502"] = "2005 + Q915793";
version9["9.00.1500"] = "2005 + Q910416";
version9["9.00.1406"] = "2005 + Q932557";
version9["9.00.1399"] = "2005";

# SQL 2000

var last_version8 = "8.00.2305";
var version8;

version8["8.00.2305"] = "2000 SP4 + MS12-060 Fix (Q983811)";
version8["8.00.2301"] = "2000 SP4 + MS12-027 Fix (Q983809)";
version8["8.00.2283"] = "2000 SP4 + Q971524";
version8["8.00.2282"] = "2000 SP4 + MS09-004 Fix (Q960083)";
version8["8.00.2279"] = "2000 SP4 + Q959678";
version8["8.00.2273"] = "2000 SP4 + Q941203 / 948111";
version8["8.00.2271"] = "2000 SP4 + Q946584";
version8["8.00.2265"] = "2000 SP4 + Q944985";
version8["8.00.2253"] = "2000 SP4 + Q939317";
version8["8.00.2249"] = "2000 SP4 + Q936232";
version8["8.00.2248"] = "2000 SP4 + Q935950";
version8["8.00.2246"] = "2000 SP4 + Q935465";
version8["8.00.2245"] = "2000 SP4 + Q933573";
version8["8.00.2244"] = "2000 SP4 + Q934203";
version8["8.00.2242"] = "2000 SP4 + Q929131 / 932686 / 932674";
version8["8.00.2238"] = "2000 SP4 + Q931932";
version8["8.00.2234"] = "2000 SP4 + Q929440 / 929131";
version8["8.00.2232"] = "2000 SP4 + Q928568";
version8["8.00.2231"] = "2000 SP4 + Q928079";
version8["8.00.2229"] = "2000 SP4 + Q927186";
version8["8.00.2226"] = "2000 SP4 + Q925684 / 925732";
version8["8.00.2223"] = "2000 SP4 + Q925678 / 925419";
version8["8.00.2218"] = "2000 SP4 + Q925297";
version8["8.00.2217"] = "2000 SP4 + Q924664";
version8["8.00.2215"] = "2000 SP4 + Q924662 / 923563 / 923327 / 923796";
version8["8.00.2209"] = "2000 SP4 + Q923797";
version8["8.00.2207"] = "2000 SP4 + Q923344";
version8["8.00.2201"] = "2000 SP4 + Q920930";
version8["8.00.2199"] = "2000 SP4 + Q919221";
version8["8.00.2197"] = "2000 SP4 + Q919133 / 919068 / 919399";
version8["8.00.2196"] = "2000 SP4 + Q919165";
version8["8.00.2194"] = "2000 SP4 + Q917972 / 917565";
version8["8.00.2192"] = "2000 SP4 + Q917606";
version8["8.00.2191"] = "2000 SP4 + Q916698 / 916950";
version8["8.00.2189"] = "2000 SP4 + Q916652 / 913438";
version8["8.00.2187"] = "2000 SP4 + Q916287";
version8["8.00.2162"] = "2000 SP4 + Q904660";
version8["8.00.2159"] = "2000 SP4 + Q907250";
version8["8.00.2151"] = "2000 SP4 + Q903742";
version8["8.00.2148"] = "2000 SP4 + Q899430";
version8["8.00.2145"] = "2000 SP4 + Q826906 / 836651";
version8["8.00.2066"] = "2000 SP4 + MS12-060 Fix (Q983812 / 983813)";
version8["8.00.2065"] = "2000 SP4 + MS12-027 Fix (Q983808)";
version8["8.00.2055"] = "2000 SP4 + MS09-004 Fix (Q959420)";
version8["8.00.2040"] = "2000 SP4 + Q899761";
version8["8.00.2039"] = "2000 SP4";
version8["8.00.2026"] = "2000 SP4 Beta";
version8["8.00.1077"] = "2000 SP2 + MS12-070 Fix (KB 983814)";
version8["8.00.818"] = "2000 SP3 + Q815495";
version8["8.00.760"] = "2000 SP3";
version8["8.00.679"] = "2000 SP2 + Q316333";
version8["8.00.667"] = "2000 SP2 + 8/14 fix";
version8["8.00.665"] = "2000 SP2 + 8/8 fix";
version8["8.00.655"] = "2000 SP2 + 7/24 fix";
version8["8.00.650"] = "2000 SP2 + Q322853";
version8["8.00.608"] = "2000 SP2 + Q319507";
version8["8.00.604"] = "2000 SP2 + 3/29 fix";
version8["8.00.578"] = "2000 SP2 + Q317979";
version8["8.00.561"] = "2000 SP2 + 1/29 fix";
version8["8.00.534"] = "2000 SP2.01";
version8["8.00.532"] = "2000 SP2";
version8["8.00.475"] = "2000 SP1 + 1/29 fix";
version8["8.00.452"] = "2000 SP1 + Q308547";
version8["8.00.444"] = "2000 SP1 + Q307540 / 307655";
version8["8.00.443"] = "2000 SP1 + Q307538";
version8["8.00.428"] = "2000 SP1 + Q304850";
version8["8.00.384"] = "2000 SP1";
version8["8.00.287"] = "2000 + Q297209";
version8["8.00.250"] = "2000 + Q291683";
version8["8.00.249"] = "2000 + Q288122";
version8["8.00.239"] = "2000 + Q285290";
version8["8.00.233"] = "2000 + Q282416";
version8["8.00.231"] = "2000 + Q282279";
version8["8.00.226"] = "2000 + Q278239";
version8["8.00.225"] = "2000 + Q281663";
version8["8.00.223"] = "2000 + Q280380";
version8["8.00.222"] = "2000 + Q281769";
version8["8.00.218"] = "2000 + Q279183";
version8["8.00.217"] = "2000 + Q279293 / 279296";
version8["8.00.211"] = "2000 + Q276329";
version8["8.00.210"] = "2000 + Q275900";
version8["8.00.205"] = "2000 + Q274330";
version8["8.00.204"] = "2000 + Q274329";
version8["8.00.194"] = "2000";
version8["8.00.190"] = "2000 Gold";
version8["8.00.100"] = "2000 Beta 2";
version8["8.00.078"] = "2000 EAP5";
version8["8.00.047"] = "2000 EAP4";

var last_version7 = "7.00.1152";
var version7;

version7["7.00.1152"] = "7.0 SP4 + Q941203 / 948113";
version7["7.00.1150"] = "7.0 SP4 + Q891116";
version7["7.00.1149"] = "7.0 SP4 + Q867763";
version7["7.00.1144"] = "7.0 SP4 + Q830233";
version7["7.00.1143"] = "7.0 SP4 + Q829015";
version7["7.00.1097"] = "7.0 SP4 + Q822756";
version7["7.00.1094"] = "7.0 SP4 + Q815495";
version7["7.00.1094"] = "7.0 SP4 + Q821279";
version7["7.00.1093"] = "7.0 SP4 + Q820788";
version7["7.00.1087"] = "7.0 SP4 + Q814693";
version7["7.00.1079"] = "7.0 SP4 + Q NA";
version7["7.00.1078"] = "7.0 SP4 + Q327068";
version7["7.00.1077"] = "7.0 SP4 + Q327068";
version7["7.00.1076"] = "7.0 SP4 + Q327068";
version7["7.00.1063"] = "7.0 SP4";
version7["7.00.1030"] = "7.0 SP3 + Q318268";
version7["7.00.1004"] = "7.0 SP3 + Q304851";
version7["7.00.996"] = "7.0 SP3 + hotfix";
version7["7.00.978"] = "7.0 SP3 + Q285870";
version7["7.00.977"] = "7.0 SP3 + Q284351";
version7["7.00.970"] = "7.0 SP3 + Q283837 / 282243";
version7["7.00.961"] = "7.0 SP3";
version7["7.00.921"] = "7.0 SP2 + Q283837";
version7["7.00.919"] = "7.0 SP2 + Q282243";
version7["7.00.918"] = "7.0 SP2 + Q280380";
version7["7.00.917"] = "7.0 SP2 + Q279180";
version7["7.00.910"] = "7.0 SP2 + Q275901";
version7["7.00.905"] = "7.0 SP2 + Q274266";
version7["7.00.889"] = "7.0 SP2 + Q243741";
version7["7.00.879"] = "7.0 SP2 + Q281185";
version7["7.00.857"] = "7.0 SP2 + Q260346";
version7["7.00.842"] = "7.0 SP2";
version7["7.00.835"] = "7.0 SP2 Beta";
version7["7.00.776"] = "7.0 SP1 + Q258087";
version7["7.00.770"] = "7.0 SP1 + Q252905";
version7["7.00.745"] = "7.0 SP1 + Q253738";
version7["7.00.722"] = "7.0 SP1 + Q239458";
version7["7.00.699"] = "7.0 SP1";
version7["7.00.689"] = "7.0 SP1 Beta";
version7["7.00.677"] = "7.0 MSDE O2K Dev";
version7["7.00.662"] = "7.0 Gold + Q232707";
version7["7.00.658"] = "7.0 Gold + Q244763";
version7["7.00.657"] = "7.0 Gold + Q229875";
version7["7.00.643"] = "7.0 Gold + Q220156";
version7["7.00.623"] = "7.0 Gold, no SP";
version7["7.00.583"] = "7.0 RC1";
version7["7.00.517"] = "7.0 Beta 3";
version7["7.00.416"] = "7.0 SP5a";
version7["7.00.415"] = "7.0 SP5 ** BAD **";
version7["7.00.339"] = "7.0 SP4 + y2k";
version7["7.00.297"] = "7.0 SP4 + SBS";
version7["7.00.281"] = "7.0 SP4";
version7["7.00.259"] = "7.0 SP3 + SBS";
version7["7.00.258"] = "7.0 SP3";
version7["7.00.252"] = "7.0 SP3 ** BAD **";
version7["7.00.240"] = "7.0 SP2";
version7["7.00.213"] = "7.0 SP1";
version7["7.00.201"] = "7.0 No SP";
version7["7.00.198"] = "7.0 Beta 1";
version7["7.00.151"] = "7.0 SP3";
version7["7.00.139"] = "7.0 SP2";
version7["7.00.124"] = "7.0 SP1";
version7["7.00.121"] = "7.0 No SP";
version7["6.50.480"] = "6.5 Post SP5a + Q238621";
version7["6.50.479"] = "6.5 Post SP5a";
version7["6.50.464"] = "6.5 SP5a + Q275483";
version7["6.50.416"] = "6.5 SP5a";
version7["6.50.415"] = "6.5 Bad SP5";
version7["6.50.339"] = "6.5 Y2K Hotfix";
version7["6.50.297"] = "6.5 Site Server 3";
version7["6.50.281"] = "6.5 SP4";
version7["6.50.259"] = "6.5 SBS only";
version7["6.50.258"] = "6.5 SP3";
version7["6.50.252"] = "6.5 Bad SP3";
version7["6.50.240"] = "6.5 SP2";
version7["6.50.213"] = "6.5 SP1";
version7["6.50.201"] = "6.5 Gold";
version7["6.00.151"] = "6.0 SP3";
version7["6.00.139"] = "6.0 SP2";
version7["6.00.124"] = "6.0 SP1";
version7["6.00.121"] = "6.0 No SP";


###
# Main
###

var port = kb_smb_transport();
var smbarch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);
var app = "Microsoft SQL Server";
var cpe = "cpe:/a:microsoft:sql_server";
var mssql_str_pattern = "^MSSQL[\d]{2}\.";
var key = "SOFTWARE\Microsoft\Microsoft SQL Server\";

var key_part, path, key_cmdexec, edition, editiontype, version, res, item;
var installs = {}, items = [], subkey, values, val, hklm, subkeys, extra = {};
var file_version, file_product_version, arch, named_instance, localdb, files_info = [];
var file_version_parts, version_parts, verbose_version, lv, report = '';


registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
subkeys = get_registry_subkeys(handle:hklm, key:key);
foreach subkey (subkeys)
{
  values = get_registry_subkeys(handle:hklm, key:key + subkey);  
  foreach val (values)
  {
    if (val == 'Setup')
    {
      append_element(var:items, value:subkey);
      break;
    }
  }
}

foreach item (items)
{
  key_part = "SOFTWARE\Microsoft\Microsoft SQL Server\" + item + "\Setup\";
  dbg::log(src:SCRIPT_NAME,
           msg:'MSSQL instance retrieved:'+ item +'\n');
  
  path = get_registry_value(handle:hklm, item:key_part + "SQLBinRoot");
  if (path) spad_log(message:'SQLBinRoot: ' + obj_rep(path));

  # if SQLBinRoot is missing, we try via CmdExec
  if (empty_or_null(path))
  {
    key_cmdexec = "SOFTWARE\Microsoft\Microsoft SQL Server\" + item + "\SQLServerAgent\SubSystems\CmdExec";
    path = get_registry_value(handle:hklm, item:key_cmdexec);
    if (!empty_or_null(path))
    {
      path = ereg_replace(pattern:"^(.*\\)[A-Za-z]+\.(DLL|dll).*", replace:"\1", string:path);
      spad_log(message:'path: ' + obj_rep(path));
    }
  }
  
  edition = get_registry_value(handle:hklm, item:key_part + "Edition");
  editiontype = get_registry_value(handle:hklm, item:key_part + "EditionType");
  key_part = "SOFTWARE\Microsoft\Microsoft SQL Server\" + item + "\MSSQLServer\CurrentVersion\";
  version = get_registry_value(handle:hklm, item:key_part + "CSDVersion");
  
  if(isnull(version))
    version = get_registry_value(handle:hklm, item:key_part + "CurrentVersion");

  # make sure we are able to verify install,
  # get a version, and not a duplicate path
  if(isnull(version) || isnull(path))
    continue;

  installs[path] = {};

  if (item =~ mssql_str_pattern)
    item = preg_replace(string:item, pattern:mssql_str_pattern, replace:'');
    
  installs[path]['named_instance'] = item;

  if ('.LOCALDB' >< item)
    installs[path]['localdb'] = TRUE;
  else
    installs[path]['localdb'] = FALSE;

  installs[path]['version'] = version;

  if(!isnull(edition)) installs[path]['edition'] = edition;
  if(!isnull(editiontype)) installs[path]['edition_type'] = editiontype;

  if ('x86' >< smbarch)
  {
    installs[path]['arch'] = 'x86';
  }
  else
  {
    res = get_registry_value(handle:hklm, item:"SOFTWARE\Wow6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL\"+item);
    if (res) installs[path]['arch'] = 'x86';
    else installs[path]['arch'] = 'x64';
  }
}

key = "SOFTWARE\Microsoft\MSSQLServer\SQLServerAgent\SubSystems\CmdExec";
path = get_registry_value(handle:hklm, item:key);

var key1;
if(!isnull(path))
{
  path =  ereg_replace(pattern:"^(.*\\)[A-Za-z]+\.(DLL|dll).*", replace:"\1", string:path);
  if(!isnull(path) && isnull(installs[path]))
  {
    key  = "SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\CurrentVersion\CSDVersion";
    key1 = "SOFTWARE\Microsoft\MSSQLServer\MSSQLServer\CurrentVersion\CurrentVersion";

    version = get_registry_value(handle:hklm, item:key);
    if(isnull(version))
      version = get_registry_value(handle:hklm, item:key1);

    if(!isnull(version))
    {
      installs[path] = {};
      installs[path]['version'] = version;
    }
  }
}

spad_log(message:'MSSQL instance(s) found: ' + obj_rep(installs));

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

var login   =  kb_smb_login();
var pass    =  kb_smb_password();
var domain  =  kb_smb_domain();

# verify installs and get sqlservr.exe file / file product version
var i, exe, exe_1, share, rc, fh, ret, tmp, children, varfileinfo, translation, stringfileinfo, data;
foreach path (keys(installs))
{
  i = strlen(path);
  if(path[i-1] == '\\')
    exe = path + 'sqlservr.exe';
  else
    exe = path + '\\sqlservr.exe';

  installs[path]['file_version'] = NULL;
  installs[path]['file_product_version'] = NULL;

  exe_1 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
  share =  hotfix_path2share(path:exe);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    continue;
  }
  fh = CreateFile(
    file:exe_1,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    ret = GetFileVersionEx(handle:fh);
    if (!isnull(ret) && !isnull(ret['dwFileVersionMS']) && !isnull(ret['dwFileVersionLS']))
    {
      tmp = [];
      tmp[0] = ret['dwFileVersionMS'] >>> 16;
      tmp[1] = ret['dwFileVersionMS'] & 0xFFFF;
      tmp[2] = ret['dwFileVersionLS'] >>> 16;
      tmp[3] = ret['dwFileVersionLS'] & 0xFFFF;

      installs[path]['file_version'] = join(tmp, sep:'.');

      if (!isnull(ret) && !isnull(ret['Children']))
      {
        children = ret['Children'];

        varfileinfo = children['VarFileInfo'];
        translation = NULL;

        if(!isnull(varfileinfo) && !isnull(varfileinfo['Translation']))
        {
          translation =
            (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
             get_word (blob:varfileinfo['Translation'], pos:2);
          translation = toupper(hexstr(mkdword(translation)));
        }

        stringfileinfo = children['StringFileInfo'];
        if (!isnull(stringfileinfo) && !isnull(translation))
        {
          data = stringfileinfo[translation];
          if (!isnull(data) && !isnull(data['ProductVersion']))
            installs[path]['file_product_version'] = data['ProductVersion'];
        }
      }
    }
    CloseFile(handle:fh);
  }
  NetUseDel(close:FALSE);
}


if (len(installs) > 1) 
  report = strcat('\nNessus detected ', len(installs), ' installs of ', app, ':\n\n');

# Register and report
foreach path (keys(installs))
{
  file_version = installs[path]['file_version'];
  if(isnull(file_version))
    continue;

  file_product_version = installs[path]['file_product_version'];

  version = installs[path]['version'];
  edition = installs[path]['edition'];
  editiontype = installs[path]['edition_type'];
  arch = installs[path]['arch'];
  named_instance = installs[path]['named_instance'];
  # extra for register_install, so downstream vuln plugins can determine if the instance is localdb or not
  localdb = installs[path]['localdb'];
  extra['localdb'] = localdb;

  if(!isnull(file_product_version))
  {
    file_version_parts = split(file_product_version, sep:'.', keep:FALSE);
    version_parts = split(version, sep:'.', keep:FALSE);

    # trust file product version over registry version
    if(max_index(file_version_parts) > 2 &&
      max_index(version_parts) > 2 &&
      (
        (int(file_version_parts[0]) != int(version_parts[0])) ||
        (int(file_version_parts[1]) != int(version_parts[1])) ||
        (int(file_version_parts[2]) != int(version_parts[2]))
      )
    )
    {
      version = file_version_parts[0] + '.';

      # exception for version string construction
      # for versions less than or equal to 9, we want to use
      # v.00 rather than v.0
      if(int(file_version_parts[0]) <= 9 && int(file_version_parts[1]) == 0)
        version += '00.';
      else version += file_version_parts[1] + '.';

      version += file_version_parts[2];

      if(!isnull(file_version_parts[3]))
        version += '.' + file_version_parts[3];
    }
  }

  verbose_version = get_verbose_version(version:version);

  if(!isnull(arch))
    set_kb_item(name:"mssql/installs/" + path + "/arch", value:arch);

  if(!isnull(edition))
    set_kb_item(name:"mssql/installs/" + path + "/edition", value:edition);

  if(!isnull(editiontype))
    set_kb_item(name:"mssql/installs/" + path + "/edition_type", value:editiontype);

  set_kb_item(name:"mssql/installs/" + path + "/SQLVersion", value:version);

  if(!isnull(verbose_version))
    set_kb_item(name:"mssql/installs/" + path + "/SQLVerboseVersion", value:verbose_version);

  set_kb_item(name:"mssql/installs/" + path + "/FileVersion", value:file_version);
  set_kb_item(name:"mssql/installs/" + path + "/FileProductVersion", value:file_product_version);

  if(!isnull(named_instance))
    set_kb_item(name:"mssql/installs/" + path + "/NamedInstance", value:named_instance);

  if (extra['localdb'] && extra['localdb'] == 1)
    set_kb_item(name:"mssql/installs/" + path + "/localdb", value:TRUE);
  else
    set_kb_item(name:"mssql/installs/" + path + "/localdb", value:FALSE);

  # collect files for vuln plugins and stores them in kb
  append_to_files_info_list(files_info:files_info, version:version, path:path, arch:arch);

  var product_version;
  if (version =~ "^6\.0\.") product_version = 'SQL6.0';
  else if (version =~ "^6\.5\d*\.") product_version = 'SQL6.5';
  else if (version =~ "^7\.0\.") product_version = 'SQL7.0';
  else if (version =~ "^8\.0\.") product_version = '2000';
  else if (version =~ "^9\.0\.") product_version = '2005';
  else if (version =~ "^10\.0\.") product_version = '2008';
  else if (version =~ "^10\.5\d*\.") product_version = '2008-R2';
  else if (version =~ "^11\.0\.") product_version = '2012';
  else if (version =~ "^12\.0\.") product_version = '2014';
  else if (version =~ "^13\.0\.") product_version = '2016';
  else if (version =~ "^14\.0\.") product_version = '2017';
  else if (version =~ "^15\.0\.") product_version = '2019';
  else if (version =~ "^16\.0\.") product_version = '2022';

  extra['arch'] = arch;
  extra['instance_name'] = get_kb_item('mssql/installs/' + path + '/NamedInstance');
  extra['local_db'] = get_kb_item('mssql/installs/' + path + '/localdb');
  share = hotfix_path2share(path:path);
  extra['is_accessible_share'] = is_accessible_share(share:share);

  register_install(
    vendor              : "Microsoft",
    product             : "SQL Server",
    app_name            : app,
    vendor              : 'Microsoft',
    product             : 'SQL Server',
    sw_edition          : editiontype,
    target_hw           : arch,
    version             : version,
    product_version     : product_version,
    path                : path,
    cpe                 : cpe,
    files               : files_info,
    extra               : extra
  );

  # build the report
  if (!empty_or_null(verbose_version))
  {
    version += ' (' + verbose_version + ')';
    report += '  Version             : ' + version + '\n';
  }
  else
  {
    report += '  Version             : ' + version + '\n';
  }

  if (!empty_or_null(edition))
    report += '  Edition             : ' + edition + '\n';

  if (!empty_or_null(path))
    report += '  Path                : ' + path + '\n';

  if (!empty_or_null(named_instance))
    report += '  Named Instance      : ' + named_instance + '\n';
  
  # Check for recommended version
  version = split(version, sep:".", keep:FALSE);

  # MSSQL <= 7
  lv = split (last_version7, sep:".", keep:FALSE);
  if ( (int(version[0]) < int(lv[0])) ||
      ( (int(version[0]) == int(lv[0])) && (int(version[1]) == int(lv[1])) && (int(version[2]) < int(lv[2])) ) )
    report += "  Recommended Version : " + last_version7 + " (" + version7[last_version7] + ').\n';

  # MSSQL 2000
  lv = split (last_version8, sep:".", keep:FALSE);
  if ( (int(version[0]) == int(lv[0])) &&
      (int(version[1]) == int(lv[1])) &&
      (int(version[2]) < int(lv[2])) )
    report += "  Recommended Version : " + last_version8 + " (" + version8[last_version8] + ').\n';

  # MSSQL 2005
  lv = split (last_version9, sep:".", keep:FALSE);
  if ( (int(version[0]) == int(lv[0])) &&
      (int(version[1]) == int(lv[1])) &&
      (int(version[2]) < int(lv[2])) )
    report += "  Recommended Version : " + last_version9 + " (" + version9[last_version9] + ').\n';

  # MSSQL 2008
  lv = split (last_version10, sep:".", keep:FALSE);
  if ( (int(version[0]) == int(lv[0])) &&
      (int(version[1]) == int(lv[1])) &&
      (int(version[2]) < int(lv[2])) )
    report += "  Recommended Version : " + last_version10 + " (" + version10[last_version10] + ').\n';

  # MSSQL 2008 R2
  lv = split (last_version10_50, sep:".", keep:FALSE);
  if ( (int(version[0]) == int(lv[0])) &&
      (int(version[1]) == int(lv[1])) &&
      (int(version[2]) < int(lv[2])) )
    report += "  Recommended Version : " + last_version10_50 + " (" + version10_50[last_version10_50] + ').\n';

  # MSSQL 2012
  lv = split (last_version11, sep:".", keep:FALSE);
  if ( (int(version[0]) == int(lv[0])) &&
      (int(version[1]) == int(lv[1])) &&
      (int(version[2]) < int(lv[2])) )
    report += "  Recommended Version : " + last_version11 + " (" + version11[last_version11] + ').\n';

  # MSSQL 2014
  lv = split (last_version12, sep:".", keep:FALSE);
  if ( (int(version[0]) == int(lv[0])) &&
      (int(version[1]) == int(lv[1])) &&
      (int(version[2]) < int(lv[2])) )
    report += "  Recommended Version : " + last_version12 + " (" + version12[last_version12] + ').\n';

  # MSSQL 2016
  lv = split (last_version16, sep:".", keep:FALSE);
  if ( (int(version[0]) == int(lv[0])) &&
      (int(version[1]) == int(lv[1])) &&
      (int(version[2]) < int(lv[2])) )
    report += "  Recommended Version : " + last_version16 + " (" + version16[last_version16] + ').\n';

  report += '\n';
}

if (report != '')
{
  set_kb_item(name:"mssql/installed", value:TRUE);

  if (report_verbosity > 0) security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
  else security_report_v4(port:port, severity:SECURITY_NOTE);
}
else
{
  audit(AUDIT_NOT_INST, 'Microsoft SQL Server');
}
