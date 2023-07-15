#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(160576);
  script_version("1.3");
  
  script_name(english:"Windows Services Registry ACL");
  script_summary(english:"Checks Registry for Service ACLs");

  script_set_attribute(attribute:"synopsis", value:"Checks Windows Registry for Service ACLs");
  script_set_attribute(attribute:"description", value:"Checks Windows Registry for Service ACLs.");

  script_set_attribute(attribute:"solution", value:"N/A");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/05");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "os_fingerprint_msrprc.nasl", "os_fingerprint_smb.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

var attack_path_analysis = script_get_preference("Attack Path Analysis");

if (empty_or_null(attack_path_analysis) || attack_path_analysis == "no")
{
    exit(0, "Attack Path Analysis not enabled.");
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");
include("global_settings.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

var keys = make_list();

keys[0] = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
keys[1] = "System\CurrentControlSet\Services";

registry_init();
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

var report = "";

foreach var k (keys)
{
    var sub_tree = get_registry_subkeys(handle:hklm, key:k);

    report += '+ HKLM/' + k + '\n';

    foreach var sub_key (sub_tree)
    {        
        report += '  - ' + sub_key + '\n';

        var sub_key_handle = RegOpenKey(handle:hklm, key:k + "\" + sub_key, mode:MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);
        var sub_key_acl = RegGetKeySecurity (handle:sub_key_handle, type:DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);

        if (!isnull(sub_key_acl))
        {
            var pdacl, access_rights, sid, type;

            var owner_sid = sid2string(sid:sub_key_acl[0]);
            var group_sid = sid2string(sid:sub_key_acl[1]);
            var sacl = sub_key_acl[2];
            var pdacl = sub_key_acl[3];

            report += "    - owner_sid : " + owner_sid + '\n';
            report += "    - group_sid : " + group_sid + '\n';

            pdacl = parse_pdacl (blob:pdacl);
            report += '    + dacl\n';

            foreach var ace (pdacl)
            {
                var access_rights_str = "";

                ace = parse_dacl(blob:ace);

                if (isnull(ace))
                {
                    continue;
                }                

                access_rights = ace[0];
                sid = sid2string(sid:ace[1]);
                type = ace[3];

                if (isnull(sid))
                {
                    continue;                    
                }

                if (access_rights & WRITE_DAC)
                {
                    access_rights_str += 'WRITE_DAC ';
                }

                if (access_rights & WRITE_OWNER)
                {
                    access_rights_str += 'WRITE_OWNER ';
                }

                if (access_rights & SYNCHRONIZE)
                {
                    access_rights_str += 'SYNCHRONIZE ';
                }

                if (access_rights & ACCESS_WRITE)
                {
                    access_rights_str += 'ACCESS_WRITE ';
                }

                if (access_rights & ACCESS_CREATE)
                {
                    access_rights_str += 'ACCESS_CREATE ';
                }

                if (access_rights & GENERIC_WRITE)
                {
                    access_rights_str += 'GENERIC_WRITE ';
                }

                report += '      - sid : ' + sid + '\n';
                report += '      - access_rights : ' + access_rights_str + '\n';

                if (type == ACCESS_DENIED_ACE_TYPE)
                {
                    report += '      - type : Deny\n';
                }
                else if (type == ACCESS_ALLOWED_ACE_TYPE)
                {
                    report += '      - type : Allow\n';
                }
                else
                {
                    continue; #unexpected
                }
            }

            RegCloseKey(handle:sub_key_handle);
        }
    }
}

RegCloseKey(handle:hklm);
close_registry();

security_note(port:kb_smb_transport(), extra:report);
