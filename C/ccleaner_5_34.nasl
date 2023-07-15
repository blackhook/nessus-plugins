#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103302);
  script_version("1.8");
  script_cvs_date("Date: 2018/11/15 20:50:16");


  script_name(english:"Piriform CCleaner 5.33.6162 Backdoor");
  script_summary(english:"Checks the version of Piriform CCleaner.");

  script_set_attribute(attribute:"synopsis", value:
"A system maintenance application installed on the remote host is
affected by a malicious backdoor.");
  script_set_attribute(attribute:"description", value:
"The version of Piriform CCleaner installed on the remote Windows
host is equal to 5.33.6162. It is, therefore, affected by a
malicious backdoor in CCleaner.exe that allows remote attackers to
obtain sensitive information and install unauthorized software.");
  # https://www.ccleaner.com/news/blog/2017/9/18/security-notification-for-ccleaner-v5336162-and-ccleaner-cloud-v1073191-for-32-bit-windows-users
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c629f18");
  # https://www.bleepingcomputer.com/news/security/ccleaner-compromised-to-distribute-malware-for-almost-a-month/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdc90ffd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Piriform CCleaner that is equal to or later than 5.34.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:piriform:ccleaner");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("ccleaner_installed.nbin");
  script_require_keys("installed_sw/CCleaner", "SMB/Registry/Enumerated", "SMB/ARCH");
  script_require_ports(139, 445);

  exit(0);
}


include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include("install_func.inc");
include("dump.inc");
include("data_protection.inc");


app_name = "CCleaner";
vuln = FALSE;
backdoor_presence_keys_data = make_array();

get_kb_item_or_exit("SMB/Registry/Enumerated");
arch = get_kb_item_or_exit("SMB/ARCH");

if (arch != "x86") audit(AUDIT_ARCH_NOT, "x86");

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

version = install['version'];
path = data_protection::sanitize_user_paths(report_text:install['path']);

###
# Look for backdoor presence in registry
###
backdoor_presence_keys = make_list(
  "SOFTWARE\Piriform\Agomo\NID",
  "SOFTWARE\Piriform\Agomo\TCID",
  "SOFTWARE\Piriform\Agomo\MUID"
);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
foreach key (backdoor_presence_keys)
{
  data = get_registry_value(handle:hklm, item:key);
  if (data)
    backdoor_presence_keys_data[key] = data;
}
RegCloseKey(handle:hklm);
close_registry();

###
# Check file version
###
if (ver_compare(ver:version, fix:"5.33.6162", strict:FALSE) == 0)
  vuln = TRUE;

if (vuln || max_index(keys(backdoor_presence_keys_data)))
{
  port = kb_smb_transport();
  if (vuln)
  {
    report =
     '\n  Path          : ' + path +
     '\n  Version       : ' + version +
     '\n  Fixed version : 5.34\n';
  }
  if (max_index(keys(backdoor_presence_keys_data)))
  {
    if (vuln)
      report += '\nAdditionally, the ';
    else
      report = '\nThe ';

    report += 'following registry keys indicate backdoor presence :\n';

    foreach key (keys(backdoor_presence_keys_data))
      report += '\n  -  Key        : ' + key +
                '\n     Value (hex): \n' + hexdump(ddata:backdoor_presence_keys_data[key]);

    report += '\n';
  }
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);  
} 
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
