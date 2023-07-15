#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60119);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_name(english:"Microsoft Windows SMB Share Permissions Enumeration");
  script_summary(english:"Enumerates network share permissions.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to enumerate the permissions of remote network shares.");
  script_set_attribute(attribute:"description", value:
"By using the supplied credentials, Nessus was able to enumerate the
permissions of network shares. User permissions are enumerated for
each network share that has a list of access control entries (ACEs).");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/bb456988.aspx");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/cc783530.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
  script_require_keys("SMB/transport", "SMB/name");
  script_require_ports(139, 445);

  exit(0);
}

include("misc_func.inc");
include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
#include("functional.inc");
include("obj.inc");
include("data_protection.inc");

global_var perm_array, perm_pad_size;
perm_array = make_array(
 ACCESS_READ,    "ACCESS_READ",
 ACCESS_WRITE,   "ACCESS_WRITE",
 ACCESS_CREATE,  "ACCESS_CREATE",
 ACCESS_EXEC,    "ACCESS_EXEC",
 ACCESS_DELETE,  "ACCESS_DELETE",
 ACCESS_ATRIB,   "ACCESS_ATRIB",
 ACCESS_PERM,    "ACCESS_PERM",
 ACCESS_GROUP,   "ACCESS_GROUP",
 ACCESS_ALL,     "ACCESS_ALL",
 DELETE,         "DELETE",
 READ_CONTROL,   "READ_CONTROL",
 WRITE_DAC,      "WRITE_DAC",
 WRITE_OWNER,    "WRITE_OWNER",
 SYNCHRONIZE,    "SYNCHRONIZE",
 STANDARD_RIGHTS_REQUIRED,  "STANDARD_RIGHTS_REQUIRED",
 STANDARD_RIGHTS_READ,      "STANDARD_RIGHTS_READ",
 STANDARD_RIGHTS_WRITE,     "STANDARD_RIGHTS_WRITE",
 STANDARD_RIGHTS_EXECUTE,   "STANDARD_RIGHTS_EXECUTE",
 STANDARD_RIGHTS_ALL,       "STANDARD_RIGHTS_ALL",
 ACCESS_SYSTEM_SECURITY,    "ACCESS_SYSTEM_SECURITY",
 MAXIMUM_ALLOWED,           "MAXIMUM_ALLOWED",
 GENERIC_READ,              "GENERIC_READ",
 GENERIC_WRITE,             "GENERIC_WRITE",
 GENERIC_ALL,               "GENERIC_ALL",
 FILE_READ_DATA,            "FILE_READ_DATA",
 FILE_LIST_DIRECTORY,       "FILE_LIST_DIRECTORY",
 FILE_WRITE_DATA,           "FILE_WRITE_DATA",
 FILE_ADD_FILE,             "FILE_ADD_FILE",
 FILE_APPEND_DATA,          "FILE_APPEND_DATA",
 FILE_ADD_SUBDIRECTORY,     "FILE_ADD_SUBDIRECTORY",
 FILE_CREATE_PIPE_INSTANCE, "FILE_CREATE_PIPE_INSTANCE",
 FILE_READ_EA,              "FILE_READ_EA",
 FILE_WRITE_EA,             "FILE_WRITE_EA",
 FILE_EXECUTE,              "FILE_EXECUTE",
 FILE_TRAVERSE,             "FILE_TRAVERSE",
 FILE_DELETE_CHILD,         "FILE_DELETE_CHILD",
 FILE_READ_ATTRIBUTES,      "FILE_READ_ATTRIBUTES",
 FILE_WRITE_ATTRIBUTES,     "FILE_WRITE_ATTRIBUTES",
 FILE_ALL_ACCESS,           "FILE_ALL_ACCESS",
 FILE_GENERIC_READ,         "FILE_GENERIC_READ",
 FILE_GENERIC_WRITE,        "FILE_GENERIC_WRITE",
 FILE_GENERIC_EXECUTE,      "FILE_GENERIC_EXECUTE"
);

_field_names = make_list();
var f;
foreach f (perm_array)
  _field_names[max_index(_field_names)] = f;
perm_pad_size = maxlen(_field_names);




function perm_item (dword, key)
{
  local_var setting;
  if (dword & key) setting = 'YES';
  else setting = 'NO';
  return '    '+perm_array[key] + ': ' +
         crap(data:' ', 
              length:(perm_pad_size-strlen(perm_array[key]))) +
         setting;
}

function permissions (dword, verbose)
{
  local_var field, fields, report, settings;
  if (!isnull(verbose) && verbose == 2) # 2 means 'Verbose'
    fields = keys(perm_array);
  else
    fields = [FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE];
  settings = make_list();
  foreach field (fields)
    settings[max_index(settings)] = perm_item(dword:dword, key:field);
  report   = '\n'+join(settings, sep:'\n');
  return report;
}

login    = kb_smb_login();
pass     = kb_smb_password();
dom      = kb_smb_domain();
port     = kb_smb_transport();
smb_name = kb_smb_name();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
ret = NetUseAdd(login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
  audit(AUDIT_SHARE_FAIL, 'IPC$');

shares = NetShareEnum(level:SHARE_INFO_502);

if (isnull(shares))
{
  NetUseDel();
  audit(code:1, AUDIT_FN_FAIL, 'NetShareEnum');
}

lsa = LsaOpenPolicy(desired_access:0x20801);
if (isnull(lsa))
{
  NetUseDel();
  audit(code:1, AUDIT_FN_FAIL, 'LsaOpenPolicy');
}

report = NULL;
num_shares = 0;  # number of shares with SDs
var share;
foreach share (shares)
{
  kb_root = 'SMB/share_permissions/' + tolower(share[0]);
  replace_kb_item(name:kb_root, value:TRUE);
  kb_root += '/';

  sd = share[9];
  if (isnull(sd)) continue;
  else num_shares++;

  owner = sid2string(sid:sd[0]);
  group = sid2string(sid:sd[1]);
  dacl = parse_pdacl(blob:sd[3]);
  if (isnull(dacl)) continue;

  report +=
    '\nShare path : \\\\' + data_protection::sanitize_user_enum(users:smb_name) + '\\' +
    data_protection::sanitize_user_enum(users:share[0]) +
    '\nLocal path : ' + share[6];

  if (share[2])
    report += '\nComment : ' + share[2];

  if (max_index(dacl) == 0)
  {
    report += '\nACEs : None\n';
    continue;
  }

  foreach ace (dacl)
  {
    ace = parse_dacl(blob:ace);
    if (isnull(ace)) continue;

    rights = ace[0];

    type = ace[3];
    sids = make_list(ace[1]);

    names = LsaLookupSid(handle:lsa, sid_array:sids);
    if (isnull(names)) continue;

    name_info = parse_lsalookupsid(data:names[0]);
    if (isnull(name_info[1]))
      name = name_info[2];
    else
      name = name_info[1] + '\\' + name_info[2];

    kb_name = kb_root + toupper(name);
    replace_kb_item(name:kb_name, value:TRUE);

    info = '\n[*] ';
    if (type == ACCESS_DENIED_ACE_TYPE)
      typestr = 'Deny';
    else if (type == ACCESS_ALLOWED_ACE_TYPE)
      typestr = 'Allow';
    else
      continue; #unexpected

    var sidstring = sid2string(sid:sids[0]);
    if (!empty_or_null(sidstring))
      sidstring = ' (S-' + sidstring + ')';

    kb_name += '/' + typestr;
    replace_kb_item(name:kb_name, value:TRUE);
    info += typestr + ' ACE for ' + name + sidstring + ': 0x'+int2hex(rights, width:8);
    info += permissions(dword:rights, verbose:report_verbosity);
    replace_kb_item(name:kb_name + '/Report', value:info);
    report += info;
  }
  report += '\n';
}
LsaClose(handle:lsa);
NetUseDel();

if (num_shares == 0)
  exit(0, 'No shares with security descriptor were enumerated on the remote host.');
else if (isnull(report))
  exit(1, 'Unknown error trying to enumerate share permissions.');

replace_kb_item(name:'SMB/share_permissions/enumerated', value:TRUE);
security_note(port:port, extra:report);

