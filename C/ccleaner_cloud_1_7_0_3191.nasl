#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103303);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:26");


  script_name(english:"Piriform CCleaner Cloud 1.07.3191 Backdoor");
  script_summary(english:"Checks the version of Piriform CCleaner Cloud.");

  script_set_attribute(attribute:"synopsis", value:
"A system maintenance application installed on the remote host is
affected by a malicious backdoor.");
  script_set_attribute(attribute:"description", value:
"The version of Piriform CCleaner Cloud installed on the remote
Windows host is equal to 1.07.3191. It is, therefore, affected by
a malicious backdoor that allows remote attackers to obtain
sensitive information and install unauthorized software.");
  # https://www.ccleaner.com/news/blog/2017/9/18/security-notification-for-ccleaner-v5336162-and-ccleaner-cloud-v1073191-for-32-bit-windows-users
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c629f18");
  # https://www.bleepingcomputer.com/news/security/ccleaner-compromised-to-distribute-malware-for-almost-a-month/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdc90ffd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Piriform CCleaner Cloud that is later than
1.07.3191. Refer to vendor advisory for further information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:piriform:ccleaner_cloud");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("ccleaner_installed.nbin");
  script_require_keys("installed_sw/CCleaner Cloud", "SMB/Registry/Enumerated", "SMB/ARCH");
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


app_name = "CCleaner Cloud";
vuln = FALSE;
backdoor_presence_keys_data = make_array();

get_kb_item_or_exit("SMB/Registry/Enumerated");
arch = get_kb_item_or_exit("SMB/ARCH");

if (arch != "x86") audit(AUDIT_ARCH_NOT, "x86");

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

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
if (ver_compare(ver:version, fix:"1.7.0.3191", strict:FALSE) == 0)
  vuln = TRUE;

if (vuln || max_index(keys(backdoor_presence_keys_data)))
{
  port = kb_smb_transport();
  if (vuln)
  {
    report =
      '\n  Path          : ' + path +
      '\n  Version       : ' + version +
      '\n  Fixed version : See Solution\n';
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
