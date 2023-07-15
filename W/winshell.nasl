#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(106629);
  script_version ("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_name(english: "WinShell Trojan Detection");
  script_summary(english: "Determines the presence of WinShell");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
  script_set_attribute(attribute:"description", value:
"This host seems to be running WinShell. WinShell is a Trojan Horse
which allows an intruder to take the control of the remote computer.

An attacker may use it to steal your passwords, modify your data, and 
prevent you from working properly.");
  script_set_attribute(attribute:"solution", value:
"Remove any instances of the WinShell Trojan and conduct a forensic
examination to determine how it was installed as well as whether
other unauthorized changes were made. Reinstall your system and
restore your system from known clean backups.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Backdoors");

  script_copyright(english:"This script is Copyright (C) 2018-2020 Tenable Network Security, Inc.");

  script_dependencie("find_service.nasl");
  script_require_ports("Services/winshell");
  exit(0);
}

include("misc_func.inc");

port = get_kb_item_or_exit("Services/winshell");

security_hole(port);
