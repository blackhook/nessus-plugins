#TRUSTED 40e6b8ed81598546a66c105c8767a1373e5a0408d79ba68533fc7bbbfc0b810cf96a1cc549b9b7a4c1da54c453c8d9520a51d1ef25d6a8dc11c12069559d920e689edb8de6aa2eedc1f99553a2113023423e0f4d8d1ac5bbc97f6c31e582eb81cc4818479491615b5df1de0efaf15a62ef3da196a10f82b8ce9410bf100560b503129b73d2a151c4c196f7d3e12cb85a4d71001a9c6218695a069155eb2163637483b307cc41bd0911a36987f979c4ac0819e338e3254e1db1e0f1a2252f427db7d5fc55db49d37ffc596052d59f65fedc7b2055d4767f8e59d93f63700bf5c4c723343a07c1b63d3d1704b1f91b935081b697d8ab1780d6631cec254d670cf92080451a44204ff5367eebaf203250d464103d8a20af0753fdbf8ad647c23e900506be62e0e22eb3ddb1b3bae8936e7629dd506daf5b5b5e26e5753082716c44583f81a9a30b9e503833be8168c6a7c740032d0a9615be9f88ad9336cf77dc9ffee90c1018d70e59f040c9d2170bab7cc4faf90318b54161b089d3e8ccc32ef1270697195913515f9f21323aa69d2fee4857203fe38cb9f00c6ef381bc8f66d94d70a87f88f2066da99e764322214dd578437188b6994a8d528e3bf8b82a7b3b46f54dd8558e4e7ba84d1c7d91f16b6d269c8935fc4a82d9d203e2607ef805c55a1d8d0e83f7b369c86094d3f1ac3fc14e077c3dd649a0c1187e5eb9580639f0
#TRUST-RSA-SHA256 0d5a9d72c3f4ccb9b2e58cebfee52b94f79958a59328e1c3fbe4e1efea87292a3c19cf8ecf4e2c28ca0ebc9d23235a810049baa233cae8752afb261099d59ae297399f6e4c5f7f72eeb985db9363709daab449d76a01b8757635da50cf79040ca6b327cf44143a5cd714af103d6a4c862548ea8afcb277c8805b27c2969e2e4c37688cb176eaf9c58ee5fd6bf70b48228a78292ecf3b3d6c4cb244fc71bf20b82eb6f8a168020118224dd7a93d459574a466309c6f5d96f4f22d32a700de8b5fd87f0f528ddc9d7162cb7a689d09177ff385ff62ef4e6b2be0a136a561b0f47c1d53e56f41953c56859596387211b5aad315c1a9cd764cb4d7c158c39430c8672feaef0c7b4c7046871a9079f06598fc53009afd6408510037992990c74512ef026d95fede2587641bf44789fd7c87a884303eade9c1152ac21b41c9e1182017dbaacb1f34501e0c7422945cf4347db30b8fea0f217b162e67841df3d551b16cbf09e617c9e7bd02b12015964d78b9c06db4f791da423195167ec0b576f597b84ff4780af90e8804908712e11c3833720f494c39ce9ad9a30a2bdb0f677d8ffddf240c423036ee808d73b784518e2a7839039f30e5d11bd2bfe5fa5541a6bc3812d850d7c7c4018bfb558c2ff62017293789e708beac51f4e64f958e591d722e295bd51cfeb6bdcc69429a2af7b51fef572ca6dac537dd5573465f17c42dd88e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14315);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/09");

  script_name(english:"Cfengine Detection");
  script_summary(english:"Detect cfengine.");

  script_set_attribute(attribute:"synopsis", value:
"The cfengine service is running on this port.");
  script_set_attribute(attribute:"description", value:
"Cfengine is a language-based system for testing and configuring
Unix systems attached to a TCP/IP network.");
  script_set_attribute(attribute:"see_also", value:"https://cfengine.com/");
  script_set_attribute(attribute:"solution", value:"N/A");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:cfengine");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2004-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "process_on_port.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");
  exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include('local_detection_nix.inc');


ldnix::init_plugin();

var ret, buf, res, ver, runner, servs, serv, report;

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

buf = info_send_cmd(cmd:"/usr/sbin/cfservd --help");
res = pregmatch(pattern:"cfengine-(\d[0-9abpc.]*)", string:buf);
if(!isnull(res))
  ver = res[1];

#FreeBSD variant
if (empty_or_null(ver))
{
  buf = info_send_cmd(cmd:"/usr/local/sbin/cfservd --help");
  res = pregmatch(pattern:"cfengine-(\d[0-9abpc.]*)", string:buf);
  if(!isnull(res))
    ver = res[1];
}

if (empty_or_null(ver))
{
  buf = info_send_cmd(cmd:"/var/cfengine/bin/cf-serverd -V");
  res = pregmatch(pattern:"^CFEngine Core\s*(\d[0-9abpc.]*)", string:buf);
  if (!isnull(res))
    ver = res[1];
}

if (info_t == INFO_SSH) ssh_close_connection();

if (isnull(ver) || "not found" >< ver)
  audit(AUDIT_NOT_INST, "cfengine");
else
  set_kb_item(name:"cfengine/version", value:ver);

runner = FALSE;

servs = get_kb_list("Host/Listeners/*");

foreach serv (servs)
{
  if(serv =~ '/cfengine/' || serv =~ '/cfservd')
    runner=TRUE;
}

if (runner)
  set_kb_item(name:"cfengine/running", value:TRUE);

report = '\n  Version  : ' + ver +'\n';

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
