#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157902);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/16");

  script_cve_id("CVE-2022-23202");
  script_xref(name:"IAVA", value:"2022-A-0073-S");

  script_name(english:"Adobe Creative Cloud Desktop Arbitrary Code Execution (APSB22-11)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Adobe Creative Cloud installer found on the remote host is 2.7.0.13 or earlier. It is, therefore, 
affected by arbitrary code execution vulnerability. An unauthenticated, local attacker could exploit this to execute
arbitrary code on an affected system.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/creative-cloud/apsb22-11.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eba9d17e");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23202");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:creative_cloud");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_creative_cloud_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Creative Cloud");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('lists.inc');
include('debug.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('installed_sw/Adobe Creative Cloud');

hotfix_check_fversion_init();
var user_paths = hotfix_get_user_dirs();
var file_pat = "(Creative_Cloud_)?Set-Up.*\.exe$"; # Creative_Cloud_Set-Up.exe / Set-Up.exe (.* before .exe to catch (N) (repeated) downloads)
var creative_cloud_installers = make_array();

# check under user dirs
foreach var user_path (user_paths)
{
    if ("Users" >< user_path)
        user_path = ereg_replace(string:user_path, pattern:"^([A-Za-z]:\\Users\\[^\\]+)(.*)", replace:"\1", icase:TRUE);
    else
        continue;
    dbg::log(src:SCRIPT_NAME, msg:'Listing files under: ' + user_path); 
    var share = hotfix_path2share(path:user_path);
    var basedir = ereg_replace(string:user_path, pattern:"^\w:(.*)", replace:"\1");
    var dir_list = list_dir(basedir:basedir, level:0, max_recurse:2, file_pat:file_pat, share:share);
    dbg::log(src:SCRIPT_NAME, msg:'List dir result: '+ obj_rep(dir_list));

    foreach var result_path (dir_list)
    {
        var installer_path = (share  - '$') + ':' + result_path;
        if (hotfix_file_exists(path:installer_path))
        {
            var fversion = hotfix_get_fversion(path:installer_path);
            hotfix_handle_error(error_code:fversion['error'], file:installer_path);
            fversion = join(fversion['value'], sep:'.');
            creative_cloud_installers[installer_path] = fversion;
        }
    }
}
hotfix_check_fversion_end();

if (empty_or_null(creative_cloud_installers))
  audit(AUDIT_NOT_INST, 'Adobe Creative Cloud (installer)');

dbg::log(src:SCRIPT_NAME, msg:'Found the following Creative Cloud Installers: ' + obj_rep(creative_cloud_installers));

var installer = branch(keys(creative_cloud_installers));
var inst_version = creative_cloud_installers[installer];

if (ver_compare(ver:inst_version, fix:'2.7.0.13', strict:FALSE) <= 0)
{
    var report =  '\n  Path              : ' + installer +
                  '\n  Installed Version : ' + inst_version +
                  '\n  Fixed version     : ' + '2.7.0.15 (installer)';
    
    security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, installer, inst_version);
