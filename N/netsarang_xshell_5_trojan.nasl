
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102713);
  script_version("1.4");
  script_cvs_date("Date: 2018/08/08 12:52:14");


  script_name(english: "NetSarang Xshell 5 Backdoor Trojan (ShadowPad)");
  script_summary(english:"Checks the Xshell 5 install for a trojaned nssock2.dll file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a trojan
backdoor.");
  script_set_attribute(attribute:"description", value:
"The Xshell 5, a terminal emulator for Windows, installed on the
remote host has a nssock2.dll file identified by its MD5 hash that
is infected with a trojan backdoor.

The affected file includes an encrypted payload that could be remotely
activated by a knowledgeable attacker.");

  script_set_attribute(attribute:"see_also", value:"https://securelist.com/shadowpad-in-corporate-networks/81432/");
  # https://www.netsarang.com/news/security_exploit_in_july_18_2017_build.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8956bf87");
  script_set_attribute(attribute:"solution", value:"Upgrade to Xshell 5 Build 1326 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);


  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

product = "Xshell 5";
trojan_hash = "97363d50a279492fda14cbab53429e75";

port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

path = get_registry_value(
  handle:hklm,
  item:"SOFTWARE\NetSarang\Xshell\5\Path"
);

RegCloseKey(handle:hklm);
close_registry(close:TRUE);

if (isnull(path))
  audit(AUDIT_NOT_INST, product);

trojan_dll = hotfix_append_path(path:path, value:"nssock2.dll");

data = hotfix_get_file_contents(trojan_dll);

if (data)
  hash = MD5(data);
else
  exit(1, "Failed to read nssock2.dll.");

if(hash == trojan_hash)
{
  report =
    '\n  Path              : ' + trojan_dll +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);

  exit(0);
}
else
{
  audit(AUDIT_INST_PATH_NOT_VULN, product, path);
}
