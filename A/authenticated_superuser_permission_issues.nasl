#TRUSTED 9b6f4181e81458b202eaa2bf8db6bc6a27057aa1c079946968398b6711fbe1abbb1881e0394818fe53e6e6c1a79276c2e30026d76d9d93868b2f353db23b3d15c1cdb54165ef40835cf3594fd212b19c7dac735df5e71bc9cedfa66b5292cffee36506dc9487ab8bd4346abf4f603775105828d4d7c9803b65ff618dd6f61d32b7d48e5464e84e64d2e01d1dd47689daf02f84ae0b3dc5ce8c13e996dc96e8019bc38ec2bc5a7d0cbc772df2450cbfdf47f779842a0aae5952c709359fe19df1fa6766ce777bcd2a88f66dd8a00ea29cb9530341da5cc0f7ad1f58b4bf7f6d716e4cfc5ef7ff643df1f62e3f055487115af3d4d722fc9f4c6fe0e539b6612bff94e15f5d17edd22e5482e0646215deb81cbbe5c492f024ef1d4845990c9a87aaaaa9ac224d06329cf6d21b0b9a53649f9c61be2d90312be04c79e75671fe5404493297c801cd1196096e245f61b484fc8a0dc8c760457c8ad81f638f49074473ba1c30a2394fc377eab12a2024c2d1ded231fbe45513e7932ed997a38f96c6e5f8dc189dd5268fe7bb23ef088704df50771c4c188878860c789f316e54122b0dccb7a7a5a4aa7d441845d7db9de2bdb56fb6e57806c4c8598e91c447427180a78b63cefd62089586c0c0269493448664a5d9982a29f89a987eba40e2adacd07ce4889500210f5d1d276ba8c7052550a00f0d5ced6b13df9a5060a4e668a7493d
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150799);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_name(english:"Target Access Problems by Authentication Protocol - Maximum Privilege Account Used in Scan");
  script_summary(english: "Reports permissions issues not related to scanning credentials.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus scanned the target host with the highest available privilege
level. Yet Nessus encountered permissions issues while accessing one
or more items during the scan.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to log in to the remote host using the provided
credentials. The provided credentials have the highest privilege
possible on the remote host.  Yet Nessus encountered permissions
issues while accessing items during the scan.

It is likely that this condition is caused by one or more of the
following:

1)  A plugin tried to access a resource that requires a special
    privilege level such as NT_AUTHORITY on Windows.  The resource
    may have had its permissions altered since the plugin was
    written.
2)  Environmental issues may have caused an intermittent failure
    in authentication that caused Nessus to stop attempting
    privilege escalation.
3)  A resource on the host that Nessus attempts to access multiple
    times may be configured with access limits.  Related lockouts may
    look like permissions failures.
4)  Nessus may have tried to access a resource that does not exist
    on a target that fails to properly report permissions issues.
    For instance, on some legacy unix systems such as AIX or HP-UX
    there is no way to distinguish a missing resource from a
    permissions error.

If you believe that the plugin indicated attempted to access the
wrong resource or a resource that has recently received special OS
protection, please contact Tenable Support.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/06");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");
include("spad_log_func.inc");
include("lcx.inc");

global_var auth_ok_count = 0;

if (platform() == 'WINDOWS')
  atts_path = nessus_get_dir(N_STATE_DIR) + "\plugins-attributes.db";
else
  atts_path = nessus_get_dir(N_STATE_DIR) + '/plugins-attributes.db';

function report_problems(prefix, proto, db, port, user)
{
  var max_privs = NULL;
  if (lcx::check_localhost() && (proto == "SMB" || proto == "SSH"))
    return 0;

  local_var kb_prefix = prefix + proto + "/" + port;
  local_var report = '';
  local_var problem_list, problem;
  local_var pattern, matches, plugin, id, atts_path, rows, pdict, plugin_id, rl;


  if (!get_kb_list(kb_prefix + "/Success")) return 0;
  auth_ok_count++;
  max_privs = get_kb_item(kb_prefix + "/MaxPrivs");
  if (!isnull(max_privs) && max_privs == 0) return 0;
  if (proto == 'SSH' && !lcx::has_ssh_priv_failures()) return 0;
  if (proto != 'SSH' && !get_kb_list(kb_prefix + "*/Problem")) return 0;

  report += '  Protocol        : ' + proto;
  report += '\n  Port            : ' + port;

  if(!isnull(max_privs))
    report = '\nNessus was able to log in to the remote host via the following' +
             '\nprotocol as ' + user  + '. This credential has the highest' +
             '\nprivilege level possible for this host. Yet Nessus encountered' +
             '\nthe following permissions issues while performing the planned checks:\n\n' + report;
  else
    report = '\nNessus was able to log in to the remote host via the following' +
             '\nprotocol as ' + user  + '. During the scan Nessus encountered' +
             '\nthe following permissions issues while performing the planned checks:\n\n' + report;

  if(proto == 'SMB')
  {
    problem_list = get_kb_list(kb_prefix + "*/Problem");
    pdict = {};
    if(!isnull(problem_list))
    {
      foreach problem(keys(problem_list))
      {
        pattern = "^" + kb_prefix + "/([\w.-_{}]+)/Problem";
        matches = pregmatch(pattern:pattern, string:problem, icase:FALSE);
        plugin_id = "<error unknown>";

        if (!isnull(matches) && !isnull(matches[1]) && db > 0)
        {
          rows = db_query(db:db, query:'SELECT * FROM Plugins WHERE plugin_fname = ?', matches[1]);
          if (!isnull(rows[0]))
            plugin_id = rows[0]['id'];
        }

        #prevent duplicate reports
        if(!isnull(pdict[plugin_id + problem]))
          continue;

        rl = "Plugin " + plugin_id;
        problem = data_protection::sanitize_user_paths(report_text:problem_list[problem]);
        rl += ":  Permission was denied while " + problem + '.\n';

        pdict[plugin_id + problem] = rl;
      }

      if(len(pdict) > 0)
      {
        report += '\n\nProblems:\n';
        foreach problem(sort(keys(pdict)))
          report += pdict[problem];

        report += '\n';
      }
    }

  }
  else if (proto == 'SSH')
  {
    report += '\n\nSee the output of the following plugin for details :\n' +
      '\n  Plugin ID   : 102094' +
      '\n  Plugin Name : SSH Commands Require Privilege Escalation\n';
  }

  if(isnull(max_privs))
    report += '\n\nNote: Nessus was unable to determine the privilege of' +
      '\n the logged in user and therefore is reporting permissions ' +
      '\n problems here.  Please check to see whether privilege escalation' +
      '\n failed or whether the scan can be configured to supply more access.\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  return 1;
}

successes = get_kb_list("Host/Auth/*/Success");

num_reported = 0;
db = 0;

pat = "^Host/Auth/([A-Za-z]+/[0-9]+)/.*";
foreach var win (keys(successes))
{
  match = pregmatch(pattern:pat, string:win, icase:FALSE);
  if (isnull(match)) continue;

  protoport = match[1];
  tmp = split(protoport, sep:'/', keep:FALSE);

  #If the first attempt to open the attributes DB fails db will equal -1. We will not try again.
  if(db == 0 && tmp[0] == 'SMB')
    db = db_open2(path:atts_path, use_default_key:TRUE, readonly:TRUE);

  num_reported += report_problems(prefix:"Host/Auth/", proto:tmp[0], port:tmp[1], db: db, user:successes[win]);
}

if(db > 0)
  db_close(db);

if (num_reported == 0)
{
  if (auth_ok_count > 0)
    exit(0, "Authentication successes did not report access or privilege issues.");
  else if (lcx::svc_available())
    exit(0, "No authentication successes using user supplied credentials to report.");
  else exit(0, "No local checks ports or services were detected.");
}

