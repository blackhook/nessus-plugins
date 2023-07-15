#TRUSTED ac6eaa4f45b5d7d353ae069ffde166fb403660fbff0c59cb5f0b7c1f827b54509fd07a6911ba15566be616cce176aab0f63cafbd36fb97946249d1ddabc13bc2b1d65278c2aa58ff230603af82a24b102ab62f65b5adbc0943d4d321472aadad761e439bdb8c785f1b6fb098bd90704369f10463b692d42905488535023ca7da2ea20c57707958446ed39d5599cad705767f2f38b960ff95eeadedf5cf1081f4e8aa7cc22e8192cd5c1f8fa979eaee1c996fcf368c72b96eb2a1d6dcb02caaeae3c258659734368988464516e37c43a195882240c1cf071050047de5b13830a7339bcaa6bb53ec7d2eed6b991767319641996991fcf111213a3b1d9d1b244c35c51d504abe266201b5319925e899f219b53f9b75936e633bb0bf9bff8265d8c146bb7902f74f00f8049693eca12be3f976e86e96c9816e9782941a9f707c4d1db248595c49d07ea2e9c96ff8fdeaf619068efe2e00c9d5969206c13cc966641c03e0e6caae6ea0a10fe6be81132319a5514466ce4016e5e2802d5fb005c0910571692364024023d9aaaf816987164a01387bcc0540e40429777ea1b5131f943fdc6d641d7e8a1b8a09a5be9210944b89a336a48d5ed489dd55ea09ca453c5de788581799afcf113a3dbaf894e9ddf8d47df01d8f772ca2bbd0c24f9d718c77eeccbd52d4f1066dfd7b6fa7cd1ee14c973b87f74f25ab8ee57fdd66d0f9159947
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122502);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/15");

  script_name(english:"Integration Credential Status by Authentication Protocol - Valid Credentials Provided");
  script_summary(english:"Reports authenticated patch management providers.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to log in to the remote patch management system
using the provided credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to execute credentialed checks because it was
possible to log in to the remote patch management system using
provided credentials.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("spad_log_func.inc");
include("lcx.inc");

function report_success(prefix, proto, db, port, user)
{
  local_var kb_prefix = prefix + proto + "/" + port;
  local_var report = '';
  local_var issues;

  issues = lcx::get_issues(type:lcx::PM_AUTH_SUCCESS, port:port,
                           user:user, proto:lcx::PROTO_GLOBALS[proto]);

  if(get_kb_list(kb_prefix + "/Failure")) return 0;
  if(max_index(issues) == 0) return 0;

  var host = issues[0].host;
  var solution = issues[0].pm_prod;

  report += '  Protocol        : ' + proto;
  report += '\n  Port            : ' + port;

  report = '\nNessus was able to log in to the ' + solution + ' host' +
           '\nat ' + host + ' as ' + user +
           '\nwith no privilege or access problems reported:\n\n' + report;

  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);

  return 1;
}

successes = get_kb_list("PManage/Auth/*/Success");

num_reported = 0;

pat = "^PManage/Auth/([A-Za-z]+/[0-9]+)/.*";
foreach var win (keys(successes))
{
  match = pregmatch(pattern:pat, string:win, icase:FALSE);
  if (isnull(match)) continue;

  protoport = match[1];

  tmp = split(protoport, sep:'/', keep:FALSE);
  num_reported += report_success(prefix:"PManage/Auth/", proto:tmp[0], port:tmp[1], user:successes[win]);
}

if (num_reported == 0)
  exit(0, "No patch management authentication successes using user supplied credentials to report.");
