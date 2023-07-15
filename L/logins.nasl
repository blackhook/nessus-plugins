#TRUSTED 9a699243ef08faebf836cfe20f4a9094b83afc16a755b51e58c5a35bdf2db8e6b80709ef505362f77ec0abaf3a46d2b02a167b6438ba82b50c5ee8f83ae127513475788438cdc6ad7698661969a7dc1c4b76e953a51c16c79b929c02eb9da9083d160221aec39661f273d55b1270265ff1653219ae4d4bd018ee461470ef0d5258776e8f9ee2b137ec555430a54a5a135b6c8443ee628d34944104a1a6c39fff21b1a936a9df0942207595d1a3711607540967cfe2f14428c856299cec93e99f18cadedd0ffd9a90392820b3645bacc14fa305e12147e9ef9abf6871d605133591f51ac631cef976b8b7d878e0ee169474e3184e960d9bce95922dadb001f1467056703d6369f4953343b6c11bab190497e319adee48a4a99a2ce5d8db3fb17a38d2dfb3ab2009a9e9af1f362d9ef545cdadbad32293da69c09a698721e9c9ed11564330ff481b694e12c7a07c4406103832b9f46796fc5a8a1729b3fa5254b76e805f0b14f7afa8781c488c3a2df453dc168f1e50fb2f497c0f4735c3d55704040712e0b4382a08c71985c8a36b2c319c84264d4e38421e4510b708cdcd5f2e860749f47b6f712555c0820ca9171279b92a63892eaf3678f46755c22f90ae88dadd8aa16409d1878875dfa13218654f08dad0c4f45ea8d4c76443319a229cc32ddcc2f27d119bfe014a1da95be8be0f492d8aca4483e74b2443f5540d2a7153
#TRUST-RSA-SHA256 61db46ba61eef58ee2fa694b02e3b578467de3462645c4b8b51fcbc1f1ed008397e18e85983062ccb088c48ba514984155901bd2c9ffd21c988708cc50ab20f4af72bf6bd9e179518023cfb86adfb5a99c22a9e4764af27c389fe31ecbd84ca94a795ec9ae295b90fb7cd8e4962f4ff0f239edb7ff108c6a32d029fe5ff9fcf23429511302cdba5084296e281bdd5ab7a551ace5a287eb1d16c928bd2f642c268d1b6712e221f4be9c555c0b7763f77e8ab1578727a016527f070bba2a3e6fcf7fd91bc1cec75b173bdabe060d6cfbe6dc022e6f4d42bc78e7ef0de3f7b49573491136d30a4a14c9d049af6d55691f1337edf3e22f64ea17f857d64a1d321dd6b5b3a63636d1039f9ea64437017b1fb48a9ac8f4440209d648d5e14431adf1a344db4dd52f31899b33fe21b27706bff39f63a6d3895ef33343456617f1225c1e1e4e51c60f39c0ea427182213726741b6935fc7af600216f1a355f9d8fb789bc2933d089f11bba19e372b8dc362fd5c986e63d391ce2cfe6bc29ebc05de015b3dc6b22dbcf4dc1e0683013604e110d738f6c820f2657517a366b1dce51eaa26f604537e6dbe35d24b2efa8a0bc6bd8dabae75febcb67520eeb5d24c80368963e1ecf8e91c8a08a0e2844f6ad4de103a9c788a050d4ea0616932b6702e1b074cb613d7e3ff69cd806076b29c6fc7260977323236bcace74af7cb53ffb587ea1b8

#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

global_var MAX_ADDITIONAL_SMB_LOGINS;
MAX_ADDITIONAL_SMB_LOGINS = 3;

if (description)
{
 script_id(10870);
 script_version("1.94");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/26");

 script_name(english:"Login configurations");
 script_summary(english:"Logins for HTTP, FTP, NNTP, POP2, POP3, IMAP, IPMI, and SMB.");

 script_set_attribute(attribute:"synopsis", value:
"Miscellaneous credentials.");
 script_set_attribute(attribute:"description", value:
"This plugin provides the username and password credentials for common
servers, such as HTTP, FTP, NNTP, POP2, POP3, IMAP, IPMI, and SMB
(NetBios).

Some plugins will use those credentials when needed. If you do not
provide the credentials, those plugins will not be able to run.

Note that this plugin does not do any security checks.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/04");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_category(ACT_SETTINGS);
 script_family(english:"Settings");

 script_dependencies("datapower_settings.nasl");

 script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_add_preference(name:"HTTP account :", type:"entry", value:"");
 script_add_preference(name:"HTTP password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"NNTP account :", type:"entry", value:"");
 script_add_preference(name:"NNTP password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"FTP account :", type:"entry", value:"anonymous");
 script_add_preference(name:"FTP password (sent in clear) :", type:"password", value:"nessus@nessus.org");
 script_add_preference(name:"FTP writeable directory :", type:"entry", value: "/incoming");

 script_add_preference(name:"POP2 account :", type:"entry", value:"");
 script_add_preference(name:"POP2 password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"POP3 account :", type:"entry", value:"");
 script_add_preference(name:"POP3 password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"IMAP account :", type:"entry", value:"");
 script_add_preference(name:"IMAP password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"IPMI account :", type:"entry", value:"");
 script_add_preference(name:"IPMI password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"SMB account :", type:"entry", value:"");
 script_add_preference(name:"SMB password :", type:"password", value:"");
 script_add_preference(name:"SMB domain (optional) :", type:"entry", value:"");
 script_add_preference(name:"SMB password type :", type:"radio", value:"Password;LM Hash;NTLM Hash");

 for ( i = 1 ; i <= MAX_ADDITIONAL_SMB_LOGINS ; i ++ )
 {
  script_add_preference(name:"Additional SMB account (" + i + ") :", type:"entry", value:"");
  script_add_preference(name:"Additional SMB password (" + i + ") :", type:"password", value:"");
  script_add_preference(name:"Additional SMB domain (optional) (" + i + ") :", type:"entry", value:"");
 }

 if(defined_func("MD5")) script_add_preference(name:"Never send SMB credentials in clear text", type:"checkbox", value:"yes");
 if(defined_func("MD5")) script_add_preference(name:"Only use NTLMv2", type:"checkbox", value:"no");
 script_add_preference(name:"Only use Kerberos authentication for SMB", type:"checkbox", value:"no");
 script_dependencies("kerberos.nasl");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ssl_funcs.inc");
include("cyberark.inc");
include("cyberarkrest.inc");
include("beyondtrust.inc");
include("lieberman.inc");
include("hashicorp.inc");
include("arcon.inc");
include("thycotic.inc");
include("centrify.inc");
include("wallix.inc");
include("delinea.inc");
include("senhasegura.inc");
include("debug.inc");

global_var result_list;

result_list = make_list();

#####
### Credential Values
#####

##
# HTTP
##
function http_credential_setup()
{
  local_var http_login, http_password, userpass, userpass64, authstr;

  http_login = script_get_preference("HTTP account :");
  http_password = script_get_preference("HTTP password (sent in clear) :");
  if (http_login)
  {
   if(http_password)
   {
    set_kb_item(name:"http/login", value:string(http_login));
    set_kb_item(name:"http/password", value:string(http_password));

    userpass = http_login + ":" + http_password;
    userpass64 = base64(str:userpass);
    authstr = "Authorization: Basic " + userpass64;
    set_kb_item(name:"http/auth", value:authstr);
   }
  }

  return NULL;
}

##
# NNTP
##
function nntp_credential_setup()
{
  local_var nntp_login, nntp_password;

  # NNTP
  nntp_login = script_get_preference("NNTP account :");
  nntp_password = script_get_preference("NNTP password (sent in clear) :");
  if (nntp_login)
  {
   if(nntp_password)
   {
    set_kb_item(name:"nntp/login", value:nntp_login);
    set_kb_item(name:"nntp/password", value:nntp_password);
   }
  }
}

##
# FTP
##
function ftp_credential_setup()
{
  local_var ftp_login, ftp_password, ftp_w_dir, ftp_auth_info;

  # FTP
  ftp_login = script_get_preference("FTP account :");
  ftp_password = script_get_preference("FTP password (sent in clear) :");
  ftp_w_dir = script_get_preference("FTP writeable directory :");

  ftp_auth_info = ftp_login+ftp_password;
  if (supplied_logins_only && ftp_auth_info == "anonymousnessus@nessus.org")
  {
    return NULL;
  }
  else
  {
    if (!ftp_w_dir) ftp_w_dir=".";
    set_kb_item(name:"ftp/writeable_dir", value:ftp_w_dir);
    if(ftp_login)
    {
      if(ftp_password)
      {
        set_kb_item(name:"ftp/login", value:ftp_login);
        set_kb_item(name:"ftp/password", value:ftp_password);
      }
    }
  }
}

##
# pop2
##
function pop2_credential_setup()
{
  local_var pop2_login, pop2_password;
  # POP2
  pop2_login = script_get_preference("POP2 account :");
  pop2_password = script_get_preference("POP2 password (sent in clear) :");
  if(pop2_login)
  {
   if(pop2_password)
   {
    set_kb_item(name:"pop2/login", value:pop2_login);
    set_kb_item(name:"pop2/password", value:pop2_password);
   }
  }
}

##
# POP3
##
function pop3_credential_setup()
{
  local_var pop3_login, pop3_password;

  pop3_login = script_get_preference("POP3 account :");
  pop3_password = script_get_preference("POP3 password (sent in clear) :");
  if(pop3_login)
  {
   if(pop3_password)
   {
    set_kb_item(name:"pop3/login", value:pop3_login);
    set_kb_item(name:"pop3/password", value:pop3_password);
   }
  }
}

##
# IMAP
##
function imap_credential_setup()
{
  local_var imap_login, imap_password;

  imap_login = script_get_preference("IMAP account :");
  imap_password = script_get_preference("IMAP password (sent in clear) :");
  if(imap_login)
  {
   if(imap_password)
   {
    set_kb_item(name:"imap/login", value:imap_login);
    set_kb_item(name:"imap/password", value:imap_password);
   }
  }
}

##
# IPMI
##
function ipmi_credential_setup()
{
  local_var ipmi_login, ipmi_password;

  ipmi_login = script_get_preference("IPMI account :");
  ipmi_password = script_get_preference("IPMI password (sent in clear) :");
  if(ipmi_login)
  {
    if(ipmi_password)
    {
     set_kb_item(name:"ipmi/login", value:ipmi_login);
     set_kb_item(name:"ipmi/password", value:ipmi_password);
    }
  }
}

##
# SMB
##
function smb_credential_setup()
{
  local_var smb_login, smb_password, smb_password_type, results_array,
  p_type, smb_domain, smb_ctxt, smb_ntv1, kdc_host, kdc_port,
  kdc_transport, kdc_use_tcp, j, i, smb_creds_prefix, smb_creds_postfix;

  var only_ntlmv2 = get_preference("Login configurations[checkbox]:Only use NTLMv2");
  var never_cleartext = get_preference("Login configurations[checkbox]:Never send SMB credentials in clear text");

  if(only_ntlmv2 == "yes" || never_cleartext == "yes")
    set_kb_item(name:"SMB/dont_send_in_cleartext", value:TRUE);

  if(only_ntlmv2 == "yes")
    set_kb_item(name:"SMB/dont_send_ntlmv1", value:TRUE);

  j = 0;
  for ( i = 0 ; i <= MAX_ADDITIONAL_SMB_LOGINS || (defined_func("nasl_level") && nasl_level() >= 6000); i ++ )
  {
    # The loop condition will succeed if i is less than MAX_ADDITIONAL_SMB_LOGINS or the nessus version is greater
    # than 6.0 . This work with a check at the end of the loop to verify that if it is greater than 6.0 we break
    # on the first set of null credentials.

    if (i > 0)
    {
      smb_creds_prefix = "Additional ";
      smb_creds_postfix = " (" + i + ") :";
    }
    else
    {
      smb_creds_prefix = "";
      smb_creds_postfix = " :";
    }

    smb_login = script_get_preference(smb_creds_prefix+"SMB account"+smb_creds_postfix);
    smb_password = script_get_preference(smb_creds_prefix+"SMB password"+smb_creds_postfix);
    smb_domain = script_get_preference(smb_creds_prefix+"SMB domain (optional)"+smb_creds_postfix);

    # In nessus >= 6 there can be different kerberos settings for each set of creds.
    # if nessus < 6, data read by kerberos.nasl is used for all creds
    kdc_host = script_get_preference(smb_creds_prefix+"SMB Kerberos KDC"+smb_creds_postfix);
    kdc_port = script_get_preference(smb_creds_prefix+"SMB Kerberos KDC Port"+smb_creds_postfix);
    kdc_transport = script_get_preference(smb_creds_prefix+"SMB Kerberos KDC Transport"+smb_creds_postfix);
    kdc_use_tcp = FALSE;
    if (!kdc_transport || ";" >< kdc_transport || kdc_transport == "tcp")
      kdc_use_tcp = TRUE;

    # this new preferences will be introduced along with Nessus 6. in order to
    # maintain backwards compatibility with policies created under older scanners,
    # the password type set by the original preference (see SMB/password_type/0 above)
    # will be used as the default value for all additional SMB accounts
    if (script_get_preference(smb_creds_prefix+"SMB password type"+smb_creds_postfix))
    {
      smb_password_type = script_get_preference(smb_creds_prefix+"SMB password type"+smb_creds_postfix);
    }
    else
    {
      smb_password_type = "";
    }

    if ("Password" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Password");
      p_type = 0;
    }
    else if ("NTLM Hash" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"NTLM Hash");
      p_type = 2;
    }
    else if ("LM Hash" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"LM Hash");
      p_type = 1;
    }
    else if ("CyberArk" >< smb_password_type)
    {
      if (script_get_preference(smb_creds_prefix+"SMB CyberArk Host"+smb_creds_postfix))
      {
        set_kb_item(name:"target/auth/method", value:"CyberArk");
        smb_password = cark_get_password(login:smb_login, domain:smb_domain, prefix:smb_creds_prefix + "SMB ", postfix:smb_creds_postfix);
        p_type = 0;
      }
      else
      {
        set_kb_item(name:"target/auth/method", value:"CyberArk REST");
        local_var cyberark_result;
        smb_creds_prefix += "SMB PAM ";
        cyberark_result = cyberark::cyberark_rest_get_credential(username:smb_login, domain:smb_domain, prefix:smb_creds_prefix, postfix:smb_creds_postfix);
        if (cyberark_result.success)
        {
          smb_password = cyberark_result.password;
          smb_login = cyberark_result.username;
          smb_domain = cyberark_result.domain;
        }
        p_type = 0;
      }
    }
    else if ("Thycotic" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Thycotic");
      smb_password = thycotic_smb_get_password(account:smb_login, prefix:smb_creds_prefix, postfix:smb_creds_postfix);
      p_type = 0;
    }
    else if ("BeyondTrust" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"BeyondTrust");
      smb_password = beyond_get_password(login:smb_login, domain:smb_domain, prefix:smb_creds_prefix + "SMB ", postfix:smb_creds_postfix);
      smb_password = smb_password.body;
      p_type = 0;
    }
    else if ("Lieberman" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Lieberman");
      smb_password = lieberman_get_password(login:smb_login, type: "OS_Windows", domain:smb_domain, prefix:smb_creds_prefix + "SMB ", postfix:smb_creds_postfix);
      smb_password = smb_password.body.Password;
      p_type = 0;
    }
    else if ("Centrify" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Centrify");
      local_var centrify_result;
      centrify_result = centrify_get_credential(username:smb_login,prefix:smb_creds_prefix+"SMB ",postfix:smb_creds_postfix);
      if (centrify_result.success){
        smb_password = centrify_result.password;
        smb_login = centrify_result.username;
        p_type = 0;
      }
    }
    else if ("Hashicorp" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Hashicorp");
      local_var hashicorp_result;
      hashicorp_result = hashicorp::get_credential(username:smb_login,prefix:smb_creds_prefix+"SMB ",postfix:smb_creds_postfix);
      if (hashicorp_result.success){
        smb_password = hashicorp_result.password;
        smb_login = hashicorp_result.username;
        if (!empty_or_null(hashicorp_result.domain)) smb_domain = hashicorp_result.domain;
        p_type = 0;
      }
    }
    else if ("Arcon" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Arcon");
      local_var arcon_result;
      arcon_result = arcon_get_credential(username:smb_login,prefix:smb_creds_prefix+"SMB ",postfix:smb_creds_postfix,type:'Windows');
      if (arcon_result.success){
        smb_password = arcon_result.password;
        smb_login = arcon_result.username;
        p_type = 0;
      }
    }
    else if ("Wallix" >< smb_password_type)
    {
      set_kb_item(name: "target/auth/method", value:"Wallix");
      var wallix_result;
      wallix_result = wallix::rest_get_credential(prefix: smb_creds_prefix+"SMB ", postfix: smb_creds_postfix);
      if (wallix_result.success)
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Successfully retrieved Wallix PAM SMB credentials.");

        smb_password = wallix_result.password;
        smb_login = wallix_result.username;
        p_type = 0;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Failed to retrieve Wallix PAM SMB credentials.");
      }
    }
    else if("Delinea" >< smb_password_type)
    {
      set_kb_item(name: "target/auth/method", value:"Delinea");
      var delinea_result;
      delinea_result = delinea_rest_get_creds(prefix: smb_creds_prefix+"SMB ", postfix: smb_creds_postfix);
      if(delinea_result.success)
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Successfully retrieved Delinea Secret Server PAM SMB credentials.");

        smb_password = delinea_result.secrets.password;
        smb_login = delinea_result.secrets.username;
        p_type = 0;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Failed to retrieve Delinea Secret Server PAM SMB credentials.");
      }
    }
    else if ("Senhasegura" >< smb_password_type)
    {
      set_kb_item(name: "target/auth/method", value:"Senhasegura");
      var senha_result;

      senha_result = senhasegura::get_credential(prefix: smb_creds_prefix+"SMB PAM ", postfix: smb_creds_postfix);

      if(senha_result.success)
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Successfully retrieved Senhasegura PAM SMB credentials.");

        smb_login = senha_result.creds.username;
        smb_password = senha_result.creds.password;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:"Failed to retrieve Senhasegura PAM SMB credentials.");
      }
    }
    else
    {
      set_kb_item(name:"target/auth/method", value:"None");
      p_type = 0;
    }

    dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:'SMB Settings: \n'+
           "  credential type: " + smb_password_type + '\n' +
           "  username: " + smb_login + '\n' +
           "  domain: " + smb_domain + '\n' +
           "  password type: " + p_type + '\n' +
           "  kdc host: " + kdc_host + '\n' +
           "  kdc port: " + kdc_port + '\n' +
           "  kdc transport: " + kdc_transport + '\n' +
           "  kdc use tcp: " + kdc_use_tcp
           );

    results_array = make_array();

    if ( smb_login && smb_password )
    {
      results_array["SMB/login_filled/" + j] = smb_login;
      results_array["SMB/password_filled/" + j] = smb_password;
      results_array["SMB/domain_filled/" + j] = smb_domain;
      results_array["SMB/cred_type/" + j] = smb_password_type;
      results_array["SMB/password_type_filled/" + j] = p_type;

      if (kdc_host && kdc_port)
      {
        results_array["SMB/kdc_hostname_filled/" + j] = kdc_host;
        results_array["SMB/kdc_port_filled/" + j] = int(kdc_port);
        results_array["SMB/kdc_use_tcp_filled/" + j] = kdc_use_tcp;
      }
      result_list[j] = results_array;
      j ++;
    }
    else if (i >= MAX_ADDITIONAL_SMB_LOGINS)
    {
      # Break at the first null credential that is above the max count of 3 for any version
      # of nessus. This is important for nessus versions greater than 6.0 .
      break;
    }

  }

  smb_insert_data();
}

##
# SMB insert data gathered
##
function smb_insert_data()
{
  local_var rl, smbi;

  foreach rl (result_list)
  {
    foreach smbi (keys(rl))
    {
      set_kb_item(name:smbi , value:rl[smbi]);
    }
  }
}

http_credential_setup();
nntp_credential_setup();
ftp_credential_setup();
pop2_credential_setup();
pop3_credential_setup();
imap_credential_setup();
ipmi_credential_setup();
smb_credential_setup();
