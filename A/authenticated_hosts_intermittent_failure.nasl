#TRUSTED 13130f9eb3655cdc6e647d8505e0fdbbf5cc44dfc8935707ae1a139549aeb76f7cf697974552c4c1fccfaef918839baa46870a5310968fb1306cb77e82462796c937a598d66b224db65135490eca4fc0926f9b0832e6b4e6eff4594120b30e079f9ff79aa04051d359e443798d6cb4665db49b663b942f343c1525c9c730e74b21e5e9716ea83dea215d5a2e48ed0db30dcc56dc8ee2e1fb32d9ad19ad41006ea4aaa1e91b2a4ab74f74f45fdaae7ea1810f1e4c64e77a4f76828fbb7e9eaa7044210cd49b864183324a275fe0059f3c040e53cd835a610cffbfa2b6c1c31955b25fc86554bb2191916ce7ae67e33a8daa9c32c848b79307adaacc6c7885d756795daa11709a502c89ed8bcae83658d2d522a5b60b1f9896b488663ae2b17752e53eaa7c9529b05db969a44f349ff61555592202af518045d8c32b4ba45707a7c3a5966596c69fc0c731d1f3abc9a9047dc2e7ef230c92609cc27354eef8f5e8b674c440793eb74f79d0acc697927b5e6c67ae8500d9df8b6078e7fa9c0bb49f1fe4a84c56e6757965c73badcdc2f53031c03e5aeddc090840e641e017eea2402c8e0023df31945e733da0f30759c6acc513df040be8e37b9344fbc0a220c3d5a7a4ebaf87872598239412b5e7284567d48b330ac4a6e87a17ffcab11141383e809b185fbaa2b0539e6cf9851fa6df28d711643af9909503f0b9a97547e10827
#TRUST-RSA-SHA256 73c47f89cb46a3debb313e275bf6c270a5838bb0ef31a8f61d39e0e4ee10e54cc82b6fc350fc89c9dfa008a8c921f0d029b867be6e6f2e90855520fe46880355fcdfc95b6a5a8d60329f40cf7c8680cfd3973299dad8acaf644b96e78e3bbbd49f44d8117de90a5e267b8991d608656dcad1b2165d862e0d75f63302dd470fd8d53c479263a5ab7834ff3416b9304a30ed1e7a75c9eff4dbdfeb408d7a82d1d5c373aa9358d3ea7efdf09f8fab19848b237aaea5d0252e5fc176a95a914ec0c5a83257fe20397a2224b3e0a6df9b90e59f632726e05bc4d1ac3e64bac6a61d5897b8ee7dd23dbdf631ae4ded7fd2db5ed5755a5a6f671e8043f78b5b70a6f5ac48a5ad37ed132dd02a7353bfe789ab59c663b94d9d7d2decc94c73c2da939d46f3afc335a878432d01844426e9f4ea077400cd605898a252b33838a834a30704665b1e14e4059400f2be5452df460f40c4f266c9d52df0d54e1699de778efa6794d184ae15f849cb6ad5bc5047a5ca23e7df556551edd4722ee2b63c290589f1d5ec006214768a4e9f5a410b8c296b3f97ab79239b430e67c3774240a66bcaea3b469ed519e5130b09592eefe879e9e35c2dff031b19086e9c762e626530a678c5b9f146661aae2c799e75d12abfe549bdbf13ac3d786adc56ac5ab5412e713efa7687524518eaf0facbc7f9609bc9d959c5040dbb5c8f2b6bc04a1017672576
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117885);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/17");

  script_xref(name:"IAVB", value:"0001-B-0509");

  script_name(english:"Target Credential Issues by Authentication Protocol - Intermittent Authentication Failure");
  script_summary(english:"Reports intermittent authentication failures on a protocol with valid credentials.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to log in to the remote host using the provided
credentials, but there were intermittent authentication failures.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to successfully authenticate to the remote host on an
authentication protocol at least once using credentials provided in
the scan policy.

However, one or more plugins failed to authenticate to the remote host
on the same port and protocol using the same credential set that was
previously successful. This may indicate an intermittent
authentication problem with the remote host, which could be caused by
session rate limits, session concurrency limits, or other issues
preventing consistent authentication success.

These intermittent authentication failures may have affected the
results of some plugins. See plugin output for failure details.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/02");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("cred_func.inc");
include("lcx.inc");

global_var auth_ok_count = 0;

function report_problems(prefix, proto, port, user)
{
  if (lcx::check_localhost() && (proto == "SMB" || proto == "SSH"))
    return 0;

  local_var kb_prefix = prefix + proto + "/" + port;
  local_var report, info, lines, stats;

  if (!get_kb_item(kb_prefix + "/Success")) return 0;
  auth_ok_count++;
  if (!get_kb_item(kb_prefix + "/Failure")) return 0;
  var proto_g = lcx::PROTO_GLOBALS[proto];
  var errs = lcx::get_issues(type:lcx::ISSUES_AUTH, port:port,
    proto:proto_g, user:user);
  if (!errs || max_index(errs) < 1) return 0;


  report = 
    '\nNessus was able to successfully log into the remote host as :\n\n';

  report += get_credential_description(proto:proto, port:port);

  var record = lcx::get_issues(type:lcx::AUTH_SUCCESS, port:port,
      proto:proto_g, user:user);
  if (record && max_index(record) > 0)
  {
    record = record[0];
    report += '\n' +
      '\nSuccessful authentication was reported by the following plugin :\n' +
      '\n  Plugin      : ' + record['plugin'];
    if (record['plugin_id']) report +=
      '\n  Plugin ID   : ' + record['plugin_id'];
    if (record['plugin_name']) report +=
      '\n  Plugin Name : ' + record['plugin_name'];
  }

  report += '\n' +
    '\nHowever, one or more subsequent plugins failed to authenticate to the' +
    '\nremote host on the same port and protocol using the same credential' +
    '\nset that previously succeeded. This may indicate an intermittent' +
    '\nauthentication problem with the remote host which may have affected' +
    '\nthe results of the following plugins.\n';

  if(get_kb_item("Host/OS/ratelimited_sonicwall"))
    report += '\nNote: Host has been identified as a SonicWall device that may be SSH rate limited.\n';
  if(get_kb_item("Host/OS/ratelimited_junos"))
    report += '\nNote: Host has been identified as Juniper Junos device that may be SSH rate limited.\n';
  if(get_kb_item("Host/OS/ratelimited_omniswitch"))
    report += '\nNote: Host has been identified as a Alcatel-Lucent OmniSwitch device that may be SSH rate limited.\n';

  # Add some stats to the top in case there are a lot of duplicates
  stats = lcx::get_issue_message_counts_text(issues:errs);
  if (stats) report += '\nError message statistics :\n\n' + stats;

  # Add details
  foreach var err (errs)
  {
    info += '\n' +
      '\n  - Plugin      : ' + err['plugin'];
    if (err['plugin_id']) info +=
      '\n    Plugin ID   : ' + err['plugin_id'];
    if (err['plugin_name']) info +=
      '\n    Plugin Name : ' + err['plugin_name'];
    info +=
      '\n    Message     : ';
    # If message is more than one line or would exceed 70 chars with
    # the label field, add a newline
    lines = split(err['text']);
    if (max_index(lines) > 1 || strlen(lines[0]) > (70 - 18))
      info += '\n';
    info += err['text'] + '\n';
  }

  if (info) report += '\nFailure Details :' + info;
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  return 1;
}

successes = get_kb_list("Host/Auth/*/Success");

num_reported = 0;

pat = "^Host/Auth/([A-Za-z]+/[0-9]+)/.*";
foreach var win (keys(successes))
{
  match = pregmatch(pattern:pat, string:win, icase:FALSE);
  if (isnull(match)) continue;

  protoport = match[1];
  tmp = split(protoport, sep:'/', keep:FALSE);
  num_reported += report_problems(prefix:"Host/Auth/", proto:tmp[0],
    port:tmp[1], user:successes[win]);
}

if (num_reported == 0)
{
  if (auth_ok_count > 0)
    exit(0, "Authentication successes did not encounter subsequent failures.");
  else if (lcx::svc_available())
    exit(0, "No authentication successes using user supplied credentials to report.");
  else exit(0, "No local checks ports or services were detected.");
}
