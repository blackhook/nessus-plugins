#TRUSTED 98ee4d7cf7e54c754636d830cb59ac30696914ed245c3fccac88d8b2ccfec2db170fe2c4670b31bb396b6fc3f5d8281f555902ef518cd112480b591f5760804c1eff8ada0d7c2523dd017f4a7329525dc9c04c75922456ecffb61fca1abd6aae326b4168cca97d0fc09360ee009f413391286d703f2c42e35c1f7d63a91d92be4bb51284a0a457ff5be190763345187279e726e3603c6c4a4668719149d8c00afba56ce3e74498c64664f69b02f4a068594da6154ae9fcb4285a85e53326909b535b2cf8a2c859574706ce692ee503b3dbe918f00adea7a233ff12c56bc3c1e7721daff39c103e0b3348c8560c1983a2ed24c247c3c263b346f61437752b36c2222a7e7e1852b7a2ff565da3f23bf9eceeef3bd4db69f38b05e0d3f29746ecebd4aa5768224fd0e81adc57dbf42bece1506799e204240c5f6cf3c2469a2bd0d3613a8852e7e3423bf439371016cfe05c231df471decf9ed92b21f0b14ea02ac2a4b4c321dede4031858a3df460192eae723c666ecf9abee41681e89c119483fc5a721edd1229bcf0b61da79d59deaea9d31398cd2ea417ec8a4db32624557560a649aa5e3f7e74b815be872838786c591a0f5fcc03a6af88de7f7c142da6bdbfe9d2f33e792d4caa21521c8c7b8ddf4d11bab6ad0e2ae49d95fa9ea41da48db491529816756ece4dddc80e9e873ddb5473cf2c9c7e3f6d71c8e5c22c6a149ff5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(90707);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/08/28");

  script_name(english:"SSH SCP Protocol Detection");
  script_summary(english:"Detects SCP support over SSH.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host supports the SCP protocol over SSH."
  );
  script_set_attribute(
    attribute:"description",
    value:"The remote host supports the Secure Copy (SCP) protocol over SSH."
  );
  script_set_attribute(attribute:"see_also",value:"https://en.wikipedia.org/wiki/Secure_copy");
  script_set_attribute(
    attribute:"solution",
    value:"n/a"
  );
  script_set_attribute(attribute:"risk_factor",value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");

  exit(0);
}

include("global_settings.inc");
include("ssh_func.inc");
include("ssh_scp_func.inc");
include("misc_func.inc");
include("obj.inc");
include("audit.inc");

if(sshlib::get_support_level() >= sshlib::SSH_LIB_SUPPORTS_LOGIN)
  enable_ssh_wrappers();
else disable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

sock_g = ssh_open_connection();
if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
info_t = INFO_SSH;

port = kb_ssh_transport();

if(!ssh_scp_init())
{
  ssh_close_connection();
  audit(AUDIT_FN_FAIL, 'ssh_scp_init');
}

ssh_scp_pull_file(location:rand_str(length:50));
ssh_close_connection();

ssh_err = tolower(get_ssh_error());

if('no such file or directory' >< ssh_err && "scp warning" >< ssh_err)
{
  set_kb_item(name:'SSH/SCP/' + port + '/Supported', value:TRUE);
  security_note(port);
}
else
{
  set_kb_item(name:'SSH/SCP/' + port + '/Supported', value:FALSE);
  exit(0, 'SCP not supported over ssh server on port ' + port + '.');
}
