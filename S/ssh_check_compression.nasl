#TRUSTED 00fc034acbcedfdb6339d5a833e0ddc77e9e402dad45badd0e08b00759dfa2ddc36f35b7c595b019a27805dd594cf5037695a9ecae5dc2faf17ed3184dc31c570354b70e3c8ead5f90b672d943f0c8f3884eaab7e02f1bf32bfd3018f118835212656d3cf63273b22c142071c1f3b796e7c350cf50d9ff9b04136960a4fc1d1c9981692f6584f0000a70393760264aada6a3667aab0ccaf5bc0117c7b53134d2e6b0a5c2a672c166f038101c2cba858bffb5a0e136ab6f1ad93495526ba08073f8bdd5e59877e3c1dbdfb18dd5fce0fc0299731dfa81284f14815ceae0398f69b9ecab4b3bf9eeeb27b63c59b8f753856b997c174ab6712186fe64b1273aa74e90ea380d85f6c86e7aa1a0640f37817aedec32ae5d8d050b9448c31a87761459ab4ea559e4845024c90672b638cc8b029c5d45f43c07859a17148d31631ce9642c85e7a9c617bd88c4ae539440f99446ea71fcd7a8cf35491215e2815d0ab0515e5f7acdda78e0e391a354999abe33a562edf1bc8f545c2477f7c7ee31e108a518ed2405ece379ab234d0158b94a800855e61ef3cd5e68713dd6f2207ea0180597c9257ff08af380d2ea62b4f125a2db5d11b23a661e6870f87684648e538c2d54718e4e58e3bacd1f3bde089fe41e28b82202396ddc1824d7b9cb7614d79db3b44127593f02c97e08f318c8e239f3c29f535120f0776ce319b36a9ba1cb6d74
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104411);
  script_version("1.8");

  script_name(english:"SSH Compression Error Checking");
  script_summary(english:"Attempts to see if ssh channels can be opened with compression.");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_set_attribute(attribute:"synopsis", value:
"The remote host supports ssh compression, but actually using ssh
compression causes errors.");
  script_set_attribute(attribute:"description", value:
"The remote host supports algorithms that can use compression. But
when ssh attempts to use compression for that communication, the
connections do not succeed.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/06");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "ssh_settings.nasl", "clrtxt_proto_settings.nasl", "ssh_rate_limiting.nasl");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

include("datetime.inc");
include("string.inc");
include("byte_func.inc");
include("misc_func.inc");

include("ssh_func.inc");
include("ssh_lib.inc");

USE_SSH_WRAPPERS = TRUE;

#start_time = gettimeofday();

enable_ssh_wrappers();

session = new("sshlib::session");
login_res = sshlib::try_ssh_kb_settings_login(session:session, accept_none_auth:FALSE);

if(!login_res)
{
  session.close_connection();
  exit(0, "The remote host is not responding to or permitting an ssh connection with the supplied credentials.");
}

if(get_kb_item("global_settings/enable_plugin_debugging"))
  SSH_DEBUG = TRUE;

if (session.compression_enabled_c_to_s == FALSE && session.compression_enabled_s_to_c == FALSE)
{
  session.close_connection();
  exit(0, "The remote host is not using an ssh connection with compression enabled.");
}

session.get_channel();
if (session.cur_state.val != "SOC_CLOSED")
{
  session.close_connection();
  exit(0, "The remote host is not experiencing any difficulty with getting a channel while ssh compression is enabled.");
}
session.close_connection();

sshlib::KEX_SUPPORTED_NAME_LISTS["compression_algorithms_server_to_client"] = "none";
sshlib::KEX_SUPPORTED_NAME_LISTS["compression_algorithms_client_to_server"] = "none";

session = new("sshlib::session");
session.open_connection(host:host, port:get_kb_item(sshlib::SSH_LIB_KB_PREFIX + "verified_login_port"));
session.login();
session.get_channel();

if (session.cur_state.val != "SOC_CLOSED")
{
  session.close_connection();
  set_kb_item(name:sshlib::SSH_LIB_KB_PREFIX + "disable_compression", value:1);
  report = 'Remote host determined to support ssh algorithms that support\ncompression, but in practice cannot successfully utilize compression.\nCompression will be disabled for ssh connections to this system.';
  security_report_v4(
    port       : session.port,
    severity   : SECURITY_NOTE,
    extra      : report
  );
  exit(0);
}
else
{
  session.close_connection();
  exit(0, "The remote host is not handling ssh connections any better with compression disabled.");
}
