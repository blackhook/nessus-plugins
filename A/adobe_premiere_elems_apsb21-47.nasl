#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150714);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/28");

  script_cve_id("CVE-2021-28623");
  script_xref(name:"IAVA", value:"2021-A-0271-S");

  script_name(english:"Adobe Premiere Elements Privilege Escalation (APSB21-47)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Adobe Premiere Elements installer found on the remote host is 5.2 or earlier. It is, therefore, 
affected by privilege escalation vulnerability. The vulnerability exists due to the creation of a temporary file with 
incorrect permissions.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/premiere_elements/apsb21-47.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c4336d7");
  script_set_attribute(attribute:"solution", value:
"Check vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28623");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_elements");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_elements_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Premiere Elements");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('lists.inc');
include('spad_log_func.inc');


get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('installed_sw/Adobe Premiere Elements');

# we need to check for the installer
hotfix_check_fversion_init();
var user_paths = hotfix_get_user_dirs();
var file_pat = "PremiereElements.*\.exe$";
var user_path;
var elements_installers = make_array();
var fixed_ver = '5.3';

# check under user dirs
foreach user_path (user_paths)
{
    if ("Users" >< user_path)
        user_path = ereg_replace(string:user_path, pattern:"^([A-Za-z]:\\Users\\[^\\]+)(.*)", replace:"\1", icase:TRUE);
    else
        continue;
    spad_log(message:'Listing files under '+user_path);
    var share = hotfix_path2share(path:user_path);
    var basedir = ereg_replace(string:user_path, pattern:"^\w:(.*)", replace:"\1");
    var dir_list = list_dir(basedir:basedir, level:0, max_recurse:2, file_pat:file_pat, share:share);
    spad_log(message:'List dir result: '+obj_rep(dir_list));
    var result_path;

    foreach result_path (dir_list)
    {
        var installer_path = (share  - '$') + ':' + result_path;
        if (hotfix_file_exists(path:installer_path))
        {
            var fversion = hotfix_get_fversion(path:installer_path);
            hotfix_handle_error(error_code:fversion['error'], file:installer_path);
            fversion = join(fversion['value'], sep:'.');
            elements_installers[installer_path] = fversion;
        }
    }
}
hotfix_check_fversion_end();

if (empty_or_null(elements_installers))
  audit(AUDIT_NOT_INST, 'Adobe Premiere Elements (installer)');

var installer = branch(keys(elements_installers));

var inst_version = elements_installers[installer];

if (ver_compare(ver:inst_version, fix:fixed_ver, strict:FALSE) == -1)
{
    report = '\n  Path              : ' + installer +
             '\n  Installed Version : ' + inst_version +
             '\n  Fixed version     : ' + fixed_ver + ' (installer)';
    
    security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, installer, inst_version);
