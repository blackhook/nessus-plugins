#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10896);
 script_version("1.20");
 script_cvs_date("Date: 2018/08/13 14:32:39");


 script_name(english:"Microsoft Windows - Users Information : Can't Change Password");
 script_summary(english:"Lists users that can not change their passwords.");

 script_set_attribute(attribute:"synopsis", value:
"At least one user can not change his or her password.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to list users who can
not change their own passwords.");
 script_set_attribute(attribute:"solution", value:
"Allow or require users to change their passwords regularly.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : User management");

 script_copyright(english:"This script is Copyright (C) 2002-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("smb_netusergetinfo.nasl");
 script_require_keys("SMB/Users/1");

 exit(0);
}

include("data_protection.inc");

start_uid = get_kb_item("SMB/dom_users/start_uid");
if(!start_uid)
 start_uid = 1000;

end_uid = get_kb_item("SMB/dom_users/end_uid");
if(!end_uid)
 end_uid = start_uid + 200;


logins = "";
count = 1;
login = get_kb_item(string("SMB/Users/", count));
while(login)
{
 acb = get_kb_item(string("SMB/Users/", count, "/Info/ACB"));
 if(acb)
 {
  if(acb & 0x40){ # UF_PASSWD_CANT_CHANGE
  	logins = string(logins, "  - ", login, "\n");
    set_kb_item(name:"SMB/Users/PwCantChange/"+count, value:login);
	}
 }
 count = count + 1;
 login = get_kb_item(string("SMB/Users/", count));
}

if(logins)
{
  if (max_index(split(logins)) == 1)
    report = "The following user can not change his/her password :\n";
  else
    report = "The following users can not change their passwords :\n";

  report = string(
    "\n",
    report,
    "\n",
    data_protection::sanitize_user_enum(users:logins),
    "\n\n",
    "Note that, in addition to the Administrator, Guest, and Kerberos\n",
    "accounts, Nessus has enumerated only those domain users with UIDs\n",
    "between ", start_uid, " and ", end_uid, ". To use a different range, edit the scan policy\n",
    "and change the 'Start UID' and/or 'End UID' preferences for \n",
    "'SMB use domain SID to enumerate users' setting, and then re-run the scan.\n"
  );
  security_note(port:0, extra:report);
}
