#TRUSTED 330286ee2129f2be950ee42ee3c45984492dd4bc6d555340eb08f62b0cd0d493b5e9797cd9f1780bd9d59f1cbbf530bdbd22a69eeab00470c2eca02ebabd88fdaa4af998dfc3145c3dd85e07b80f97d0f30ed2f0386a45fcfb25f5bf54ea392a69a62f3b7c6b784e901814189946cd325ff7ef3418b86ed9061912dd97505f273a7e18858a69242766bc3af27ab1cd401761230e953878c076408281a9d01ba230ebd17df56b7ffd22ac29e068a80bcbc3857bc5ba62ed2462bf751537dab60b67ff799d2b015b26dec39986f2013c843d9e8a4d4f9ca1bb22532c3beb4c0df8d3506c3d031f15a13661725bb7c5dc41ecce48185916c78a32b00006d7219c269d4d02c92115f3d97719e0920761a5caa58826c2d73c0a155033b5efe89402003564bf1dbf6f36347ffb541077250be534b30bcd99d374a04295f17efb1a9d286329f562697df45cb87df0aaef88e892a7225ffd3445a81a9d474a0890d08af276f424f6a1230b365ba65e82c3f0613d5aeae0e80aa6f695cfcae58e9d63e1625b6c6eb10a2ca65126893357a8679f907458bb6fbd3217672436f758ea4f9a65d25800870709d9ff10e1dd34892436f6a5246ef8fe10d2ec9ce869c97997fe9df88d3c46652b9a3a760911549364e62aed055890013c97631bd4f509317655229dd33990c7162f817c9da1aeb7beae7ab174e8cc271444cd36115554b071e664
#
# (C) Tenable Network Security, Inc.
#
# @@NOTE: The output of this plugin should not be changed
#
#
#

include("compat.inc");

if(description)
{
  script_id(10267);
  script_version("2.30");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/22");

  script_xref(name:"IAVT", value:"0001-T-0933");

  script_name(english:"SSH Server Type and Version Information");
  script_summary(english:"SSH Server type and version.");

  script_set_attribute(attribute:"synopsis", value:
"An SSH server is listening on this port.");
  script_set_attribute(attribute:"description", value:
"It is possible to obtain information about the remote SSH server by
sending an empty authentication request.");
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"solution", value:"n/a" );

  script_set_attribute(attribute:"plugin_publication_date", value: "1999/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2002-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_ports("Services/ssh", 22);
  script_dependencies("find_service1.nasl", "find_service2.nasl", "external_svc_ident.nasl", "ssh_check_compression.nasl");

  exit(0);
}


#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

# This plugin uses the first SSH credential, not necessarily the
# correct SSH credential - authentication does not need to succeed
checking_default_account_dont_report = TRUE;

enable_ssh_wrappers();

if (get_kb_item("global_settings/supplied_logins_only"))
  supplied_logins_only = 1;
else
  supplied_logins_only = 0;

port = get_kb_item("Services/ssh");

if (!port) port = 22;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "SSH");

version = NULL;
if (defined_func("bn_random"))
{
  _ssh_socket = open_sock_tcp(port);
  if ( ! _ssh_socket ) audit(AUDIT_SOCK_FAIL, port, "SSH");
  login = kb_ssh_login();
  password = kb_ssh_password();
  pub = kb_ssh_publickey();
  priv = kb_ssh_privatekey();
  passphrase = kb_ssh_passphrase();
  realm = kb_ssh_realm();
  host = kb_ssh_host();
  nofingerprint = FALSE;
  if (isnull(login) && !supplied_logins_only)
  {
    login = "n3ssus";
    password = "n3ssus";
    pub = NULL;
    priv = NULL;
    passphrase = NULL;
    nofingerprint = TRUE;
  }

  ssh_login (login:login, password:password, pub:pub, priv:priv, passphrase:passphrase, realm:realm, host:host, nofingerprint:nofingerprint);

  version = get_ssh_server_version ();
  banner = get_ssh_banner ();
  supported = get_ssh_supported_authentication ();
  key = get_server_public_key();
  ssh_close_connection();
}

if ( empty_or_null(version) )
{
  soc = open_sock_tcp(port);
  if ( ! soc ) audit(AUDIT_SOCK_FAIL, port, "SSH");
  version = recv_line(socket:soc, length:4096);
  if ( !preg(pattern:"^SSH-", string:version ) ) audit(AUDIT_SERVICE_VER_FAIL, "SSH", port);
  close(soc);
}

if (!version) audit(AUDIT_SERVICE_VER_FAIL, "SSH", port);

set_kb_item(name:"SSH/banner/" + port, value:version);
text = "SSH version : " + version + '\n';

if (supported)
{
  set_kb_item(name:"SSH/supportedauth/" + port, value:supported);
  text += 'SSH supported authentication : ' + supported + '\n';
}

if (banner)
{
  set_kb_item(name:"SSH/textbanner/" + port, value:banner);
  text += 'SSH banner : \n' + banner + '\n';
}

if (key)
{
  fingerprint = hexstr(MD5(key));
  fingerprint_sha256 = hexstr(SHA256(key));
  b64_key = base64(str:key);

  if ("ssh-rsa" >< key)
  {
    set_kb_item(name:"SSH/Fingerprint/ssh-rsa/"+port, value:fingerprint);
    set_kb_item(name:"SSH/Fingerprint/sha256/ssh-rsa/"+port, value:fingerprint_sha256);
    set_kb_item(name:"SSH/publickey/ssh-rsa/"+port, value:b64_key);
  }
  else if ("ssh-dss" >< key)
  {
    set_kb_item(name:"SSH/Fingerprint/ssh-dss/"+port, value:fingerprint);
    set_kb_item(name:"SSH/Fingerprint/sha256/ssh-dss/"+port, value:fingerprint_sha256);
    set_kb_item(name:"SSH/publickey/ssh-dss/"+port, value:b64_key);
  }
  else if("ecdsa" >< key)
  {
    set_kb_item(name:"SSH/Fingerprint/ecdsa/"+port, value:fingerprint);
    set_kb_item(name:"SSH/Fingerprint/sha256/ecdsa/"+port, value:fingerprint_sha256);
    set_kb_item(name:"SSH/publickey/ecdsa/"+port, value:b64_key);
  }
}

report = '\n' + text;

security_note(port:port, extra:report);
register_service(port:port, proto: "ssh");
