#TRUSTED 695ec19da6ef63be20d3f24c89e1247977f35eab9ff669360294f38557332cfeb36241ac011cee9b4ba2b709ca94feef3555206f67c41044bb380da01d52084b226eeb8273a58e1e1a38884432a9859c097d4c5943c66aaeea075c4b4cf4e99695d72fe674dc174581b56d3901f3e35464bc6d83e7d0f72a713c66faab5ff649779cd7c32fd6d35182f8dd7cd774151ae50b76a9a0f60a17acc00d64d34fe7743822f725e13170c118a3091f837635508e5060d144f4272d263cdb3edd31088b9e45d8d1cd2f4edcdf2e7ded0e295bfc15a000ba92fa559f92ba5ca640072cd4d22751690b626f72cae1b06752ea5d2e5190abf46167637247238f4007e8d3c9ffab0655eda8867af31596eb77b4d591840bef4903f5a64cb1124a8acfcf10041abedf76e14cbc06f70ee1cf6056695e3eddf742482971791b051bc87b0242a5fb11e31806d5a969e6c94e04f822ea4e41f58ef99c4547ff71428d8c05c10a76d073d2135f589cbe3829f4904296977e3aefcfbd2a6f86e1d6a5a092916a487ee796e765be5c0868e91c4b7a884000dc6ba34464a18ea59dc0da49cc851e50d46a6ad9faac068ef86b9850a1d71fa8cc405f19034fb1216f86f5e527ae58ec251b00cf943875e9f636ebcda3e82fd438f5f14b63579c7ef7013003f1e5b737551acc29b5b3ad49d8f8c9981c1aa837eb028ab36a29325a0e740ce66460edbe2f
#TRUST-RSA-SHA256 541e88ba808bf69d7e12fe6cb129b2e411d8195ecb3187e5a8904d2630941bf571ca7c6782410321cc07e3bba6aa104630bbdd8d46e6723f6d4bd534ad9234d8c1ce9bbf92db3ba424938ae843e19b74ae193f471661378be49026d0335c82316978dad35b2aac636740885fe7e7ceaa6c0c52090e54a0b5095a7312da134ce1169593f93a50de1dfafd652ceb75ca483a69a06a943f97be0fd0817ea503d3d68b90466d46f29d6635c11885138f10d54c021c99973edb9680c62fc6115281ae6ab8ff700419ece06e42be65945938f2a0139b2f42b6c7756a9d545644292c582e4a126545a9efc315a1ab9a6af7cde0cedb4bf1eccdacf205535e9b6831c733f30ec54eb6f02af21ea298f8a9108c873d6364f80bece695fdb06ce87cb3fdffd0857265d26185fe84a6215edc17ffd1b0a37cbf5d5349b040953add4f2a20ad7594c98feda7a2bc772bbe26af11df9d3d7d3f35ede70274c5b1d5cf4f33f007882c01d4f07341f7d55916cda994d4011078cf8501e48f73df85ef178979917ec5d82c7cb0ce6e12e33ed268b71b0819077f8c1bf81abcfefeb8d6e491a88c89855b7b94878ae404164d3efde485ac4fae14ade4ac095470191307216cc464c3e379b5b4fefe1257950dcb6e194d4a68dbd67c61a69cde81f4a684972f902be8d044fe19f8df5f559a6e60f02d622a2fcdd5809e6ed6478160cda76febec2b81
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70136);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_name(english:"Cisco Content Switching Module (CSM) Software Version");
  script_summary(english:"Gets the CSM version");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the CSM software version of the remote Cisco
device.");
  script_set_attribute(attribute:"description", value:
"The remote host has a Cisco Content Switching Module (CSM). 

It is possible to read the CSM software version by connecting to the
switch using SSH.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisco.com/c/en/us/products/interfaces-modules/content-switching-module/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:cisco_content_switching_module");

  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("install_func.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_COMMANDS ||
    get_one_kb_item('HostLevelChecks/proto') == 'local')
  enable_ssh_wrappers();
else disable_ssh_wrappers();

# Verify that the target system is running Cisco IOS.
get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Require local checks be enabled.
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Try to extract the CSM software version from the "show module
# version" command.
cmd = "show module version";
sock_g = ssh_open_connection();
if (!sock_g) exit(0, "Failed to open an SSH connection.");
res = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
ssh_close_connection();

if (isnull(res)) exit(1, "Failed to execute '" + cmd + "' on the remote host.");

mods = make_list(
  "WS-X6066-SLB-APC",
  "WS-X6066-SLB-S-K9"
);

re = NULL;
foreach mod (mods)
{
  if (mod >< res)
  {
    # This regex needs to match the following example paragraphs:
    #
    # 4 4 WS-X6066-SLB-APC SAD093004BD Hw : 1.7
    # Fw :
    # Sw : 4.2(3a)
    #
    # 4 4 WS-X6066-SLB-S-K9 SAD093004BD Hw : 1.7
    # Fw :
    # Sw : 2.1(3)
    re = "\d\s+\d\s+" + mod + ".+[\r\n]Fw.+[\r\n]Sw\s*:\s*([0-9a-z][0-9a-z\.\(\)]+)";
    break;
  }
}

if (isnull(re)) exit(1, "Failed to find any CSM modules in the output of '" + cmd + "'.");

matches = pregmatch(string:res, pattern:re);
if (isnull(matches)) exit(1, "Failed to parse the version number of the CSM module on the remote host.");
ver = matches[1];

kb = "Host/Cisco/CSMSW";
set_kb_item(name:kb, value:TRUE);
set_kb_item(name:kb + "/Module", value:mod);
set_kb_item(name:kb + "/Version", value:ver);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Module  : ' + mod +
    '\n  Version : ' + ver +
    '\n';
}

register_install(
  vendor:"Cisco",
  product:"Cisco Content Switching Module",
  app_name:'CSMSW',
  path:"/",
  version:ver,
  cpe:"cpe:/a:cisco:cisco_content_switching_module"
);

security_note(port:0, extra:report);
