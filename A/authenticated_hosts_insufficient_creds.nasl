#TRUSTED 827410a7ccc66f3ccde37db121dcb76bc9e3c6b82632ebdf670c73094f31d8de26590def2f8c03d03143d89e56dda2f9069206fe626d7a9d079e4629abd1863d7d4912973cbe6dab96e8b1809938f7dbd83eabeafa1ea2b0ce6538fd1962e39c4aca80c3d1629c676e154138dc7311be53016cb8a6e2f9b8aa516ced30eb5648c09df17ce72e53698da5cc26a4b63872a4044c3ac0dcf8ff42bc78791828b96ac883487968dc95bab96f73e8ae8aac1cb764aff9ee2bf991733d5a43f6bab026894b9efb75127c1d3705537b48372e14eb9b3c2b1013b205aa082bfd1f1925989c143a0e2804fb3932e12c544f688618fd1cf7773ee40888ff1100e692b6cf52817b3e34fbda78e8882bad751989f4930a3225e90724545c7da9c8fc079acd775e983dee69ebccf388fec6c43bf347a0820e83223eb409de0d615fdd90bba95b9a03f4ff2d6dd86b43f35f7a4c410642bbeb8bf4e21cd9f249eb23bfc166d464edf33bbe090dfe9b10cbd5dac926cd578ec2435033d0d3bbdbf8d0a78262a6cf042039e7cde03071540a89abe40e746a5be5b7b2557c2fc88a847917150caa180c5141b67e35fc5494008533be3c599fc264d77025c1b0a2de7422b6ede61750b3de28f23dc165cc7ebdd2ca8f19a9a5ce5524900dcb1dd1af41d35ef5c8f9bf610839f8471fd10cd7e6b69285bf6127d4983e08a5cf7d2e36899866253489e7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110385);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/26");

  script_xref(name:"IAVB", value:"0001-B-0502");

  script_name(english:"Target Credential Issues by Authentication Protocol - Insufficient Privilege");
  script_summary(english: "Reports insufficient privilege issues encountered on a protocol with valid credentials.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to log in to the remote host using the provided
credentials. The provided credentials were not sufficient to complete
all requested checks.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to execute credentialed checks because it was
possible to log in to the remote host using provided credentials,
however the credentials were not sufficiently privileged to complete
all requested checks.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/06");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");
include("spad_log_func.inc");
include("cred_func.inc");
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
  if (isnull(max_privs) || max_privs == 1) return 0;
  if (proto == 'SSH' && !lcx::has_ssh_priv_failures()) return 0;
  if (proto != 'SSH' && !get_kb_list(kb_prefix + "*/Problem")) return 0;

  report += get_credential_description(proto:proto, port:port);

  report = '\nNessus was able to log into the remote host, however this credential' +
           '\ndid not have sufficient privileges for all planned checks :\n\n' + report;

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
    exit(0, "Authentication successes; did not report insufficient credential issues.");
  else if (lcx::svc_available())
    exit(0, "No authentication successes using user supplied credentials to report.");
  else exit(0, "No local checks ports or services were detected.");
}

