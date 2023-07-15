#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10914);
 script_version("1.22");
 script_cvs_date("Date: 2019/07/08 10:52:29");


 script_name(english:"Microsoft Windows - Local Users Information : Never Changed Passwords");
 script_summary(english:"Lists local users who have never changed their passwords.");

 script_set_attribute(attribute:"synopsis", value:
"At least one local user has never changed his or her password.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to list local users
who have never changed their passwords.");
 script_set_attribute(attribute:"solution", value:
"Allow or require users to change their passwords regularly.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/17");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : User management");

 script_copyright(english:"This script is Copyright (C) 2002-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("smb_netusergetinfo_local.nasl");
 script_require_keys("SMB/LocalUsers/enumerated");

 exit(0);
}

include ("data_protection.inc");

get_kb_item_or_exit("SMB/LocalUsers/enumerated");

start_uid = get_kb_item("SMB/local_users/start_uid");
if(!start_uid)
 start_uid = 1000;

end_uid = get_kb_item("SMB/local_users/end_uid");
if(!end_uid)
 end_uid = start_uid + 200;


logins = "";
count = 1;
login = get_kb_item("SMB/LocalUsers/" + count);
while(login)
{
 p = get_kb_item("SMB/LocalUsers/" + count + "/Info/PassLastSet");
 if(!isnull(p) && p == 0)
 {
    logins = logins + "  - " + login + '\n';
    set_kb_item(name:"SMB/LocalUsers/NeverChangedPw/"+count, value:login);
 }
 count = count + 1;
 login = get_kb_item("SMB/LocalUsers/" + count);
}

if(logins)
{
  if (max_index(split(logins)) == 1)
    report = "The following local user has never changed his/her password :\n";
  else
    report = "The following local users have never changed their passwords :\n";

  logins = data_protection::sanitize_user_enum(users:logins);
  report = '\n' + report + '\n' + logins + '\n\n' +
   'Note that, in addition to the Administrator and Guest accounts, Nessus\n' +
   "has only checked for local users with UIDs between " + start_uid + " and " + end_uid + '.\n' +
   "To use a different range, edit the scan policy and change the 'Start" + '\n' +
   "UID' and/or 'End UID' preferences for 'SMB use host SID to enumerate" + '\n' +
   "local users' setting, and then re-run the scan." + '\n';

  security_note(port:0, extra:report);
}
