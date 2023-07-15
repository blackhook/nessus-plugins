#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100718);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/07");

  script_cve_id("CVE-2016-8939");
  script_bugtraq_id(98783);

  script_name(english:"IBM Spectrum Protect Client Windows Registry Credentials Disclosure");
  script_summary(english:"Checks for insecure permissions of registry key for IBM Spectrum Protect Client.");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Spectrum Protect Client installed on the remote
Windows host is affected by an information disclosure vulnerability
due to insecure permission for registry keys under the
'HKLM\Software\IBM\ADSM\CurrentVersion\Nodes\' key. A local attacker
can exploit this vulnerability to disclose credentials.

IBM Spectrum Protect was formerly known as IBM Tivoli Storage Manager
in releases prior to version 7.1.3.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22003738");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg22000998");
  script_set_attribute(attribute:"see_also", value:"https://improsec.com/blog/vulnerability-in-tsm");
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory for instructions on remediation.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8939");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:spectrum_protect_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tivoli_storage_manager_client_installed.nasl", "ibm_spectrum_protect_installed.nbin", "tivoli_storage_manager_virtual_environments_installed.nbin");
  script_require_ports(139, 445, "installed_sw/Tivoli Storage Manager Client", "installed_sw/IBM Spectrum Protect", "installed_sw/Tivoli Storage Manager for Virtual Environments");

  exit(0);
}

include("audit.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("lists.inc");

function reg_key_readable_by_users_group(security_descriptor)
{
  local_var pdacl, dacl, item, access_rights, sid;
  local_var USERS_SID, REG_ACCESS_READ;

  USERS_SID = "1-5-32-545";
  REG_ACCESS_READ = 0x0020019;

  pdacl = security_descriptor[3];
  pdacl = parse_pdacl(blob:pdacl);
  if (empty_or_null(pdacl))
    return NULL;

  foreach item (pdacl)
  {
    dacl = parse_dacl(blob:item);
    if (empty_or_null(dacl)) continue;

    # SID check
    sid = sid2string(sid:dacl[1]);
    if (empty_or_null(sid)) continue;
    if (sid != USERS_SID) continue;

    # Access rights
    access_rights = dacl[0];
    if (empty_or_null(access_rights)) continue;

    if (access_rights == REG_ACCESS_READ)
      return TRUE;
  }
  return FALSE;
}

apps = ["Tivoli Storage Manager Client","IBM Spectrum Protect","Tivoli Storage Manager for Virtual Environments"];
installed = FALSE;

foreach app (apps) 
{
  if (get_install_count(app_name:app))
  {
    installed = TRUE;
    break;
  }
}
if (!installed) audit(AUDIT_NOT_INST, "IBM Spectrum Protect client / agent");

vuln_keys = [];

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "Software\IBM\ADSM\CurrentVersion\Nodes";
subkeys = get_registry_subkeys(handle:hklm, key:key, wow:TRUE);

foreach item (keys(subkeys))
{
  foreach subkey (subkeys[item])
  {
    working_key = item + "\" + subkey;
    key_h = RegOpenKey(handle:hklm, key:working_key, mode:MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);
    if(!isnull(key_h))
    {
      # Make sure 'Password' value exists
      if (!isnull(get_registry_value(handle:hklm, item:working_key + "\Password")))
      {
        # Check if Read permissions are granted to Users group
        security_descriptor = RegGetKeySecurity(handle:key_h, type:DACL_SECURITY_INFORMATION);
        if (!isnull(security_descriptor))
        {
          vuln = reg_key_readable_by_users_group(security_descriptor:security_descriptor);
          if (vuln) collib::push("HKLM\"+working_key, list:vuln_keys);
        }
      }
      RegCloseKey (handle:key_h);
    }
  }
}

RegCloseKey (handle:hklm);
NetUseDel();

if (empty_or_null(vuln_keys))
  exit(0, "The install of IBM Spectrum Protect client / agent is not using a vulnerable configuration.");

wording = NULL;
if (max_index(vuln_keys) == 1)
  wording = "key is";
else
  wording = "keys are";

report =
  '\n The following registry '+wording+' vulnerable :' +
  '\n' +
  '\n  - ' + join(vuln_keys, sep:'\n  - ') +
  '\n';

security_report_v4(port:kb_smb_transport(), extra:report, severity:SECURITY_NOTE);
