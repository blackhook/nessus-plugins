#TRUSTED b12b2e0728b3657954321e1a41b4d17316b85835d00780c59891f3d4106cfb2cdbedd4037c132d608d6835e64a2cbc872828ce19ac4c3459de08a532525523f957fb45b955059fa1e209d9f47bc764c8d93c85c039513ab2e766316fe9964fde2d5c2918af3fe33dde0eaec98cfe27973f4abec36e4d4c72abc26fa80ffadcf94eab070ffae130b32a88773ef25c15b965f734971a474baaf8ec4e6b0c928f072c5bc6d5b66796af2e28528f3c2edd93cecd4fff9e304c21919c4f72e883ffe8beb07a0cba357c027dc36d0d54ee3b80b18968198513bad08cf92d5883724674a51743523ee2ea87602f1e6a25016f0092862b5c38334ca55ffcaf02718cf034206834e5e00fd8ffe6019418bd509f739a490befb3d4dbe5aa3f549f53518a5fdc30296a50c33653c4b8dc07803277d6295aa659053efe0ebe986dccdbcf4868311efa26132821db38f25f750c3d98d8e3e6e72a561bf499b1b5cd49a2afa7e897ead47c6166ea36d09e0629c53b7037ff3b8bf8ef1a5a322aa29ec8d889c6e0c939f1fb6d8205e3fbad7f7e4041dc945bfc3e81e961a610672536183b51fe854b66cc0cb0ee84a3bc20e38211c7b6377930f3933930e831dbc2361cdacc9a7def4151e32b749a791c5acfb38c71092076258177e683ca2d4f2dcb69a32b8b0f6e9967598dd0beb46a46ce89fa48c7e8de8021f38b4cbe7c632c037a3d4055ec
#TRUST-RSA-SHA256 1f34081ad18395c10bfc7f167e729ecb0f0d1619a7535ca54ae3580500ca6c06802ec79580479c283fee40d8e18b287fb402a115b7f153c98e65b645577937f028765efc2323a22a41f0a3da866a6c9a9adafd4a6ed223f34722b425738e0ef3816a22e5a407e75efe0dce24df80d94e6025c03aa27ba5e5614218aa9a77c4bd3a2f71fb5fb5fee6310eafa59d971bd47835a1e8540bf21739357e232c29ba9192c5faad40a86d2d8c7f6bac4a3a89e9ad0089a84d8998c67353cc88587f0c54312ed9a4a83261f9de6d2f70c132782b983ec72d31b2a4fdf61a74a5f4772f1c3001c87311b49ceeea3d1a7c67ba206db595d0d68ee9aaae0b3ced6db7c621b53136a13c4e2648b3903f55aa6e8c3613c0315d127058e86fc12a3ec6d740379e82c6e9cabfdcada551acd26e963ba54d3a92611a876f7a659b912da3c8b22ae2eae6b10b02855d8719f07d57f8bf2096e5afc1a729b457f5fcb18f10ec1bfa8af4a26d5b78ecbde7f40a34b4f14a2dc4990e5aa2d1bb73e36c673a2414ede96db2bff9f4cd653c3fe185285e4defb572c4815eacccb166d847e612fde7c2e59d57a8c94b03f718f2e167ff70acaec7cc960d1ffe781fc40281b0e93f66a7588421adbb31900082ad318d59be492c980f2c8d54f33afca2262e8bed73f89457248e888a7735168b5d8bc41c884138949ace5f1af13fcadcd53923f526e6bbfdb9

#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(14273);
 script_version("1.123");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/05");

 script_name(english:"SSH settings");
 script_summary(english:"Set SSH keys & user name to perform local security checks.");

 script_set_attribute(attribute:"synopsis", value:
"This plugin configures the SSH subsystem.");
 script_set_attribute(attribute:"description", value:
"This plugin initializes the SSH credentials as set by the user.

To set the credentials, edit your scan policy and go to the section
'Credentials'.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/15");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_family(english:"Settings");

 script_dependencies("datapower_settings.nasl");

 script_category(ACT_INIT);

 script_copyright(english:"This script is Copyright (C) 2004-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("global_settings.nasl");

 if (defined_func("bn_random"))
 {
   script_add_preference(name:"SSH user name : ",
                       type:"entry",
                       value:"root");
   script_add_preference(name:"SSH password (unsafe!) : ",
                       type:"password",
                       value:"");
   script_add_preference(name:"SSH public key to use : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"SSH private key to use : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"Passphrase for SSH key : ",
                       type:"password",
                       value:"");
  script_add_preference(name:"Elevate privileges with : ",
                       type:"radio",
                       value:"Nothing;sudo;su;su+sudo;dzdo;pbrun;Cisco 'enable'");
  script_add_preference(name:"Privilege elevation binary path (directory) : ",
                       type:"entry",
                       value:"");
  script_add_preference(name:"su login : ",
                       type:"entry",
                       value:"");
  script_add_preference(name:"Escalation account : ",
                       type:"entry",
                       value:"root");
  script_add_preference(name:"Escalation password : ",
                       type:"password",
                       value:"");
  script_add_preference(name:"SSH known_hosts file : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"Preferred SSH port : ",
                       type:"entry",
                       value:"22");
  script_add_preference(name:"Client version : ",
                       type:"entry",
                       value:"OpenSSH_5.0");

  for ( i = 1 ; i <= 5 ; i ++ )
  {
   script_add_preference(name:"Additional SSH user name (" + i + ") : ",
                       type:"entry",
                       value:"");
   script_add_preference(name:"Additional SSH password (" + i + ") : ",
                       type:"password",
                       value:"");
  }
 }

 exit(0);
}

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
include("ssh_func.inc");
include("thycotic.inc");
include("centrify.inc");
include("wallix.inc");
include("delinea.inc");
include("senhasegura.inc");
include("debug.inc");

dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:
  'SSH Settings Plugin Loaded');

enable_ssh_wrappers();

global_var ssh_settings_last_error;

ssh_settings_last_error = "";

##
# Determines if the given hostname patterns match the current target
#
# The man page for sshd(8) says:
#
# "Hostnames is a comma-separated list of patterns (`*' and `?' act as
#  wildcards); each pattern in turn is matched against the canonical host
#  name (when authenticating a client) or against the user-supplied name
#  (when authenticating a server).  A pattern may also be preceded by `!' to
#  indicate negation: if the host name matches a negated pattern, it is not
#  accepted (by that line) even if it matched another pattern on the line.
#  A hostname or address may optionally be enclosed within `[' and `]'
#  brackets then followed by `:' and a non-standard port number"
#
# @anonparam patterns a comma delimited list of patterns
# @return TRUE if the IP or hostname of the current target matches any patterns,
#         FALSE otherwise
##
function patterns_match_this_host()
{
  var patterns, port, pattern, match, negated, target_ip, target_hostname;
  patterns = split(_FCT_ANON_ARGS[0], sep:',', keep:FALSE);
  port = _FCT_ANON_ARGS[1];
  if (isnull(port)) port = 22;

  match = FALSE;
  target_ip = get_host_ip();
  target_hostname = get_host_name();

  foreach pattern (patterns)
  {
    negated = FALSE;
    if (pattern[0] == '!')
    {
      negated = TRUE;
      pattern = substr(pattern, 1);
    }

    if (pattern =~ "^\[.*\]:[0-9]+") # key with non-standard port, e.g., [ssh.example.net]:2222
    {
      if (
        pattern == '[' + target_ip + ']:' + port ||
        pattern == '[' + target_hostname + ']:' + port
      )
      {
        if (negated) return FALSE; # a negated pattern takes precedence over all other patterns
        match = TRUE;
      }
    }
    else
    {
      pattern = str_replace(string:pattern, find:'.', replace:"\.");
      pattern = str_replace(string:pattern, find:'*', replace:".*");
      pattern = str_replace(string:pattern, find:'?', replace:".");
      pattern = '^' + pattern + '$';

      if (
        preg(string:target_ip, pattern:pattern) ||
        preg(string:target_hostname, pattern:pattern, icase:TRUE)
      )
      {
        if (negated) return FALSE; # a negated pattern takes precedence over all other patterns
        match = TRUE;
      }
    }
  }

  return match;
}

##
# Log the errors associated with this plugin
##
function ssh_settings_log_error(error)
{
  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:error);
  ssh_settings_last_error = error;
}

##
# Get last error logged
##
function ssh_settings_get_last_error()
{
  return ssh_settings_last_error;
}

##
# Gather ssh settings from the UI and store them in the kb for access
#
# @return list of the ssh creds
##
function ssh_settings_get_settings()
{
  var client_ver, pref_port, i, j, jindex, ssh_prefix, ssh_postfix, ssh_pub_key_cert,
    account,private_key,passphrase,password,kdc,kdc_port,kdc_transport,realm,sudo,result_list,
    su_login,sudo_path,root,sudo_password,result_array,EsclPwdType,
    cert, ssh_pw_warning, least_priv, beyond_creds,
    lieberman_creds, custom_prompt, auth_type, auto_accept, target_priority_list;

  ###
  ## Begin global preferences
  ###
  EsclPwdType = "sudo";
  client_ver  = script_get_preference("Client version : ");
  pref_port = script_get_preference("Preferred SSH port : ");
  least_priv = script_get_preference("attempt_least_privilege");
  auto_accept = get_kb_item('Settings/automatically_accept_disclaimer');
  result_list = make_list();

  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
    'SSH Settings Initializing : \n' +
    "  Client Verison:" + client_ver + '\n'+
    "  Port:" + pref_port + '\n' +
    "  Least Priv:" + least_priv + '\n' +
    "  Auto-accept disclaimers:" + auto_accept + '\n'
    );

  ##
  # j is used to keep track of the current successfully gathered creds to
  # insert into the kb. The kb needs to be inserted starting with no counter
  # and increase in numerical order string at 0 and not skipping any values.
  # kb first  /SSH/value/test = X
  # kb second /SSH/value/0/test = X
  # kb third  /SSH/value/1/test = X
  ##
  j = 0;

  ##
  # Loop through all credentials and store the values in an array
  # to be indexed later for scan storage.
  # The array is used instead of direct insert to be able to easily
  # access the values for any normalization or generic manipulation.
  ##
  for (i=0;i<1000;i++)
  {
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'SSH Settings Credential Loop '+i);

    if (i > 0)
    {
      ssh_prefix = "Additional "; # additional creds add the "Additional" prefix
      ssh_postfix = " ("+i+") : "; # additional creds are followed by an index value

      # The additional instances of the public key/cert will use
      # a different string parameter displayed here.
      ssh_pub_key_cert = "Additional SSH certificate to use ("+i+") : ";

      # additional passwords do not have the unsafe warning
      ssh_pw_warning =  "";
    }
    else
    {
      ssh_prefix = ""; # first instance does not have a prefix
      ssh_postfix = " : "; # there is no index into the first instance of parameters

      # The first instance of the public key/cert will use
      # a different string parameter displayed here.
      ssh_pub_key_cert = "SSH public key to use : ";

      # The first instance of the password field has the unsafe title
      ssh_pw_warning =  " (unsafe!)";
    }

    if (j > 0)
    {
      # create the index value to be stored in the KB. The value is j-1 because we start
      # counting kb index values at 0.
      jindex = "/"+(j-1)+"/"; # define the index value into the KB
    }
    else
    {
      # The first index value will always be stored without an int index
      jindex = "/"; # define no index into the KB
    }

    # Get password type or username. Break if none supplied.
    auth_type = script_get_preference(ssh_prefix+"SSH password type"+ssh_postfix);
    account =  script_get_preference(ssh_prefix+"SSH user name"+ssh_postfix);
    account = string(account);

    if(isnull(auth_type) && strlen(account) < 1)
    {
      if ( COMMAND_LINE ) break;
      if ( i <= 5 ) continue;
      else break;
    }
    else dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Password Type :'+ auth_type);

    cert = script_get_preference_file_content(ssh_pub_key_cert);
    private_key = script_get_preference_file_content(ssh_prefix+"SSH private key to use"+ssh_postfix);
    passphrase  = script_get_preference(ssh_prefix+"Passphrase for SSH key"+ssh_postfix);
    password = script_get_preference(ssh_prefix+"SSH password"+ssh_pw_warning+ssh_postfix);
    custom_prompt = script_get_preference(ssh_prefix+"SSH custom password prompt"+ssh_postfix);
    target_priority_list = script_get_preference(ssh_prefix+"Targets to prioritize credentials"+ssh_postfix);
    kdc = script_get_preference(ssh_prefix+"Kerberos KDC"+ssh_postfix);
    kdc_port = script_get_preference(ssh_prefix+"Kerberos KDC Port"+ssh_postfix);
    kdc_transport = script_get_preference(ssh_prefix+"Kerberos KDC Transport"+ssh_postfix);
    realm = script_get_preference(ssh_prefix+"Kerberos Realm"+ssh_postfix);

    # For additional elevate priv only attempt to read the new privilege elevation preferences when running at Nessus 6 compatibility or later.
    # on scanners running at older than Nessus 6 compatibility, the values read from the original privilege elevation preferences above will be reused
    # a policy is using the new Nessus 6 preferences if the following one is present
    if (script_get_preference(ssh_prefix+"Elevate privileges with"+ssh_postfix))
    {
      sudo = script_get_preference(ssh_prefix+"Elevate privileges with"+ssh_postfix);
      su_login = script_get_preference(ssh_prefix+"su login"+ssh_postfix);
      sudo_path = script_get_preference(ssh_prefix+"Privilege elevation binary path (directory)"+ssh_postfix);
      root = script_get_preference(ssh_prefix+"Escalation account"+ssh_postfix);

      if (root !~ "^[A-Za-z][A-Za-z0-9_.-]+$")
      {
        root = "root";
      }

      sudo_password = script_get_preference(ssh_prefix+"Escalation password"+ssh_postfix);
    }
    #
    # Gather beyondtrust creds
    #
    if ("BeyondTrust" >< auth_type || script_get_preference(ssh_prefix+"SSH BeyondTrust Host"+ssh_postfix))
    {
      beyond_creds = beyond_get_password(login:account, prefix:ssh_prefix + "SSH ", postfix:ssh_postfix);
      if (beyond_creds.privatekey)
      {
        private_key = beyond_creds.privatekey;
        passphrase = beyond_creds.body;
      }
      else
      {
        password = beyond_creds.body;
      }

      if (beyond_creds.elevation_command)
      {
        # currently password safe will only ever list
        # "sudo", "pbrun", or "pmrun" as the elevation command
        if (beyond_creds.elevation_command == "sudo")
        {
          sudo = "sudo";
        }
        else if (beyond_creds.elevation_command == "pbrun")
        {
          sudo = "pbrun";
        }
        else
        {
          dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
            "unsupported elevation command: " + beyond_creds.elevation_command);
        }

        if (beyond_creds.private_key)
        {
          sudo_password = beyond_creds.password.body;
        }
        else
        {
          sudo_password = password;
        }
      }
    }
    #
    # Gather lieberman creds
    #
    if ("Lieberman" >< auth_type || script_get_preference(ssh_prefix+"SSH Lieberman Host"+ssh_postfix))
    {
      lieberman_creds = lieberman_get_password(login:account, type: "OS_UnixAndCompat", prefix:ssh_prefix + "SSH ", postfix:ssh_postfix);
      password = lieberman_creds.body.Password;
    }
    #
    # Gather cyberark creds
    #
    if ("CyberArk" >< auth_type || script_get_preference(ssh_prefix+"SSH CyberArk Host"+ssh_postfix))
    {
      var cyberark_result;

      if (script_get_preference(ssh_prefix+"SSH CyberArk Host"+ssh_postfix))
      {
        cyberark_result = cyberark_get_credential(username:account, prefix:ssh_prefix, postfix:ssh_postfix);

        if (cyberark_result.success)
        {
          password = cyberark_result.password;
          sudo = cyberark_result.sudo;
          sudo_password = cyberark_result.sudo_password;
          su_login = cyberark_result.su_login;
          sudo_path = cyberark_result.sudo_path;
          root = cyberark_result.root;
          private_key = cyberark_result.private_key;
        }
      }
      else
      {
        ssh_prefix += "SSH PAM ";
        cyberark_result = cyberark::cyberark_rest_get_credential(username:account, prefix:ssh_prefix, postfix:ssh_postfix);

        if (cyberark_result.success)
        {
          password = cyberark_result.password;
          account = cyberark_result.username;
          sudo_password = cyberark_result.sudo_password;
          private_key = cyberark_result.ssh_key;
        }
      }
    }
    #
    # Gather Thycotic Creds
    #
    if ("Thycotic" >< auth_type)
    {
      var thycotic_result;
      thycotic_result = thycotic_get_credential(username:account,prefix:ssh_prefix,postfix:ssh_postfix);

      if (thycotic_result.success)
      {
        password = thycotic_result.password;
        sudo = thycotic_result.sudo;
        sudo_password = thycotic_result.sudo_password;
        su_login = thycotic_result.su_login;
        sudo_path = thycotic_result.sudo_path;
        root = thycotic_result.root;
        private_key = thycotic_result.private_key;
        passphrase = thycotic_result.passphrase;
      }
    }
    #
    # Centrify
    #
    if ("Centrify" >< auth_type)
    {
      var centrify_result;

      centrify_result = centrify_get_credential(username:account,prefix:ssh_prefix+"SSH ",postfix:ssh_postfix);

      if (centrify_result.success)
      {
        password = centrify_result.password;
        account = centrify_result.username;
      }
    }
    #
    # Hashicorp
    #
    if ("Hashicorp" >< auth_type)
    {
      var hashicorp_result;

      hashicorp_result = hashicorp::get_credential(username:account, prefix:ssh_prefix+"SSH ", postfix:ssh_postfix);

      if (hashicorp_result.success)
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
          "Successfully got Hashicorp PAM credentials.");
        password = hashicorp_result.password;
        account = hashicorp_result.username;
        sudo_password = hashicorp_result.sudo_password;
      }
    }
    #
    # Arcon
    #
    if ("Arcon" >< auth_type)
    {
      var arcon_result;

      arcon_result = arcon_get_credential(username:account, prefix:ssh_prefix + "SSH ", postfix:ssh_postfix, type:'Linux');

      if (arcon_result.success)
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
          "Successfully got Arcon PAM credentials.");

        password = arcon_result.password;
        account = arcon_result.username;
        sudo = arcon_result.sudo;
        sudo_password = arcon_result.sudo_password;
        sudo_path = arcon_result.sudo_path;
        su_login = arcon_result.su_login;
        root = arcon_result.root;
      }
    }
    #
    # Wallix
    #
    if ("Wallix" >< auth_type)
    {
      var wallix_result;

      wallix_result = wallix::rest_get_credential(prefix:ssh_prefix+"SSH ", postfix:ssh_postfix);

      if (wallix_result.success)
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
          "Successfully retrieved Wallix PAM SSH credentials.");

        password = wallix_result.password;
        account = wallix_result.username;
        sudo_password = wallix_result.sudo_password;
        private_key = wallix_result.private_key;
        passphrase = wallix_result.passphrase;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
          "Failed to retrieve Wallix PAM SSH credentials.");
      }
    }
    #
    # Delinea
    #
    if("Delinea" >< auth_type)
    {
      var delinea_result;

      delinea_result = delinea_rest_get_creds(prefix:ssh_prefix+"SSH ", postfix:ssh_postfix);
      dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
        "The response from Delinea is: " + delinea_result.success);

      if(delinea_result.success)
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
          "Successfully retrieved Delinea Secret Server PAM SSH credentials.");

        account = delinea_result.secrets.username;
        password = delinea_result.secrets.password;
        sudo_password = delinea_result.secrets.sudo_password;
        private_key = delinea_result.secrets.key;
        passphrase = delinea_result.secrets.passphrase;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
          "Failed to retrieve Delinea Secret Server PAM SSH credentials.");
      }
    }
    #
    # Senhasegura
    #
    if ("Senhasegura" >< auth_type)
    {
      var senha_result;

      senha_result = senhasegura::get_credential(prefix:ssh_prefix+"SSH PAM ", postfix:ssh_postfix);

      if(senha_result.success)
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg: 
          "Successfully retrieved Senhasegura PAM SSH credentials.");

        account = senha_result.creds.username;
        password = senha_result.creds.password;
        sudo_password = senha_result.creds.sudo_password;
        private_key = senha_result.creds.private_key;
        passphrase = senha_result.creds.passphrase;
      }
      else
      {
        dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:
          "Failed to retrieve Senhasegura PAM SSH credentials.");
      }
    }
    ##
    # USE THIS SPACE TO EXPAND NEW PASSWORD MANAGERS
    ##

    # if no credentials are set continue to the next instance. Changing from isnull() to empty_or_null().
    # when PAM's do not return a cred, the password var from script_get_preference() ln 317 retains it's "value"
    # of empty and not NULL. As a result, isnull(password) returns 0.
    if (empty_or_null(password) && empty_or_null(private_key))
    {
      #no credentials set for user account
      ssh_settings_log_error(error:'No credentials set for account (' + account + ')');

      continue;
    }

    dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
      'SSH Settings : \n'+
      "  credential type:" + auth_type + '\n' +
      "  username:" + account + '\n' +
      "  elevate user:" + root + '\n' +
      "  elevate with:" + sudo + '\n'
    );

    # storage for credentials information
    result_array = make_array();
    if (j == 0)
    {
      # these values are single instance storage value or legacy values and only need set one time.

      if (!isnull(cert)) result_array["Secret/SSH/publickey"] = cert; #less than nessus 6 only
      if (!isnull(kdc)) result_array["Secret/kdc_hostname"] = kdc; #less than nessus 6 only
      if (!isnull(kdc_port)) result_array["Secret/kdc_port"] = int(kdc_port); #less than nessus 6 only
      if (!kdc_transport || ";" >< kdc_transport || kdc_transport == "tcp")
        result_array["Secret/kdc_use_tcp"] = TRUE; #less than nessus 6 only

      if (!isnull(client_ver)) result_array["SSH/clientver"] = client_ver; #global
      if (!isnull(pref_port) && int(pref_port) ) result_array["Secret/SSH/PreferredPort"] = int(pref_port); # global
      if (least_priv == "yes") result_array["SSH/attempt_least_privilege"] = TRUE;
    }

    if (!isnull(account)) result_array["Secret/SSH"+jindex+"login"] = string(account);
    if (!isnull(root)) result_array["Secret/SSH"+jindex+"root"] = string(root);
    if (!isnull(cert)) result_array["Secret/SSH"+jindex+"certificate"] = string(cert);
    if (!isnull(private_key)) result_array["Secret/SSH"+jindex+"privatekey"] = hexstr(private_key);
    if (!isnull(passphrase)) result_array["Secret/SSH"+jindex+"passphrase"] = string(passphrase);
    if (!isnull(password)) result_array["Secret/SSH"+jindex+"password"] = string(password);
    if (!isnull(custom_prompt)) result_array["SSH"+jindex+"custom_password_prompt"] = string(custom_prompt);
    if (!empty_or_null(target_priority_list)) result_array["SSH"+jindex+"target_priority_list"] = string(target_priority_list);
    if (!isnull(auth_type)) result_array["SSH"+jindex+"cred_type"] = string(auth_type);

    # save Kerberos preferences
    if (kdc && kdc_port && realm)
    {
      result_array["Secret/SSH"+jindex+"kdc_hostname"] = string(kdc);
      result_array["Secret/SSH"+jindex+"kdc_port"] = int(kdc_port);
      result_array["Kerberos/SSH"+jindex+"realm"] = string(realm);

      if (!kdc_transport || ";" >< kdc_transport || kdc_transport == "tcp")
        result_array["Kerberos/SSH"+jindex+"kdc_use_tcp"] = TRUE;
    }

    EsclPwdType = "sudo";
    if ( sudo == "sudo" ) result_array["Secret/SSH"+jindex+"sudo"] = SU_SUDO;
    else if ( sudo == "su" ) result_array["Secret/SSH"+jindex+"sudo"] = SU_SU;
    else if ( sudo == "su+sudo") result_array["Secret/SSH"+jindex+"sudo"] = SU_SU_AND_SUDO;
    else if ( sudo == "dzdo" ) result_array["Secret/SSH"+jindex+"sudo"] = SU_DZDO;
    else if ( sudo == "pbrun" ) result_array["Secret/SSH"+jindex+"sudo"] = SU_PBRUN;
    else if ( sudo == "Cisco 'enable'" ) EsclPwdType = "Cisco enable";
    else if ( sudo == "Checkpoint Gaia 'expert'" ) EsclPwdType = "Checkpoint expert";

    if (sudo) result_array["Secret/SSH"+jindex+"sudo_method"] = sudo;
    if (su_login =~ '^[A-Za-z0-9._-]+$') result_array["Secret/SSH"+jindex+"su-login"] = string(su_login);
    sudo_password = string(sudo_password);
    if(strlen(sudo_password) > 0)
    {
      if (EsclPwdType == "sudo" )
        result_array["Secret/SSH"+jindex+"sudo-password"] = sudo_password;
      else if (EsclPwdType == "Cisco enable")
        result_array["Secret/SSH"+jindex+"enable-password"] = sudo_password;
      else if (EsclPwdType == "Checkpoint expert")
        result_array["Secret/SSH"+jindex+"expert-password"] = sudo_password;
    }
    if (sudo && sudo_path && preg(pattern:"^[A-Za-z0-9./-]+$", string:sudo_path))
    {
      if (!preg(pattern:"/$", string:sudo_path)) sudo_path += '/';
      result_array["Secret/SSH"+jindex+"sudo_path"] = string(sudo_path);
    }

    result_list[j] = result_array;
    j++; # increase the index counter for the kb entry
  }

  return result_list;
}

##
# Takes the input from ssh_settings_get_settings()
# to input into the kb.
#
# @param [ssh_settings:list] list of array values to get inserted in the kb
#
###
function insert_ssh_settings_kb(ssh_settings)
{
  var sshi, sshk;

  foreach sshi (ssh_settings)
  {
    foreach sshk (keys(sshi))
    {
      set_kb_item(name:sshk, value:sshi[sshk]);
    }
  }
}

##
# set ssh_settings known host information
##
function ssh_settings_known_host()
{
  var file,known_hosts,lines,line,data,pref_port,port,revoked,
    ca,tmp,hostname,type,key,cert,h_s,hn,ip,e,n;

  known_hosts = script_get_preference_file_content("SSH known_hosts file : ");
  # If running from command line, prompt for known_hosts file
  if (isnull(get_preference("plugins_folder")))
  {
    file = script_get_preference("SSH known_hosts file : ");
    display('\n');
    if(!empty_or_null(file))
    {
      known_hosts = fread(file);
      if(!known_hosts)
      {
        display("Could not read the file ", file, "\n");
        exit(1);
      }
    }
  }

  if ( ! isnull(known_hosts) )
  {
    lines = split(known_hosts, keep:FALSE);
    foreach line ( lines )
    {
      # The man page for sshd(8) says "Lines starting with `#' and empty lines are ignored as comments."
      if (line =~ "^\s*#" || line =~ "^\s*$") continue;

      data = split(line, sep:' ', keep:FALSE);
      if ( pref_port && int(pref_port) ) port = pref_port;
      else port = 22;

      revoked = FALSE;
      ca = FALSE;
      if (data[0] == '@revoked' || data[0] == '@cert-authority')
      {
        if (data[0] == '@revoked')
          revoked = TRUE;
        if (data[0] == '@cert-authority')
          ca = TRUE;

        tmp = make_list(data[1], data[2], data[3]);
        data = tmp;
      }

     # if the second field (index 1) is _not_ all numeric (i.e. is not the bits field), this line refers to an SSH2 key or certificate
     if ( data[1] !~ "^\d+$" && max_index(data) >= 3)
     {
      hostname = data[0];
      type = data[1];
      key = data[2];

      # if a certificate was provided instead of a key, retrieve the host's public key from the cert
      if ("-cert-" >< type)
      {
        cert = base64decode(str:key);
        cert = parse_ssh_cert(cert);
        key = get_public_key_from_cert(cert);
        if (isnull(key)) continue; # key will only be NULL if the public key type is unknown or unsupported

        if ("ssh-rsa" >< type)
          type = "ssh-rsa";
        if ("ssh-dss" >< type)
          type = "ssh-dss";
        if ("ssh-ed25519" >< type)
          type = "ssh-ed25519";
        key = base64encode(str:key);
      }

      if ( revoked && patterns_match_this_host(hostname, port) )
      {
        set_kb_item(name:"SSH/RevokedKey", value:key);
      }
      else if ( ca && patterns_match_this_host(hostname, port) )
      {
        set_kb_item(name:"SSH/CAKey", value:key);
      }
      else if ( hostname =~ "^\|1\|" )  # HMAC_SHA1 hash of the hostname
      {
        hostname -= "|1|";
        h_s = split(hostname, sep:'|', keep:FALSE);
        if ( base64decode(str:h_s[1]) == HMAC_SHA1(key:base64decode(str:h_s[0]), data:get_host_ip()) ||
             base64decode(str:h_s[1]) == HMAC_SHA1(key:base64decode(str:h_s[0]), data:'[' + get_host_ip() + ']:' + port) ||
             base64decode(str:h_s[1]) == HMAC_SHA1(key:base64decode(str:h_s[0]), data:'[' + get_host_name() + ']:' + port) ||
             base64decode(str:h_s[1]) == HMAC_SHA1(key:base64decode(str:h_s[0]), data:get_host_name() + ',' + get_host_ip()) ||
             base64decode(str:h_s[1]) == HMAC_SHA1(key:base64decode(str:h_s[0]), data:get_host_name()) )
        {
          replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
        }
      }
      else if ( hostname =~ "^\[.*\]:[0-9]+" )
      {
        if ( hostname == "[" + get_host_ip() + "]:"+ port  ||
             hostname == "[" + get_host_name() + "]:"+ port )
          replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
      }
      else if ( "," >!< hostname )
      {
        if ( hostname == get_host_ip() || hostname == get_host_name() )
          replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
      }
      else
      {
        hn = ereg_replace(pattern:"^([^,]*),.*", string:hostname, replace:"\1");
        ip = ereg_replace(pattern:"^[^,]*,(.*)", string:hostname, replace:"\1");
        if ( ip == get_host_ip() && hn == get_host_name() )
        {
          replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
        }
      }
     }
     # if fields 2-4 (indices 1-3) _are_ all numeric (the bits, exponent, and modulus fields), this line refers to an SSH1 key
     else if ( data[1] =~ "^\d+$" && data[2] =~ "^\d+$" && data[3] =~ "\d+$")
     {
      hostname = data[0];
      e = data[2];
      n = data[3];
      if ( hostname == get_host_ip() || hostname == get_host_name() )
      {
        replace_kb_item(name:"SSH/KnownFingerprint/ssh-rsa1", value:e + "|" + n);
      }
     }
   }

   #This section initializes known fingerprints to the base64 encoding of @NOTSET@
   #The string "@NOTSET@" in base64 is QE5PVFNFVEA=
   if ( ! get_kb_item("SSH/KnownFingerprint/ssh-rsa1") )
     set_kb_item(name:"SSH/KnownFingerprint/ssh-rsa1", value:"QE5PVFNFVEA=");

   # this lets sshlib know that a host key was not provided for this host.
   # (It is not possible to use CAs with ssh-rsa1)
   if ( ! get_kb_list("SSH/CAKey") )
   {
     if ( ! get_kb_item("SSH/KnownFingerprint/ssh-rsa"))
       set_kb_item(name:"SSH/KnownFingerprint/ssh-rsa", value:"QE5PVFNFVEA=");

     if ( ! get_kb_item("SSH/KnownFingerprint/ssh-dss"))
       set_kb_item(name:"SSH/KnownFingerprint/ssh-dss", value:"QE5PVFNFVEA=");

     if ( ! get_kb_item("SSH/KnownFingerprint/ecdsa-sha2-nistp256"))
       set_kb_item(name:"SSH/KnownFingerprint/ecdsa-sha2-nistp256", value:"QE5PVFNFVEA=");

     if ( ! get_kb_item("SSH/KnownFingerprint/ecdsa-sha2-nistp384"))
       set_kb_item(name:"SSH/KnownFingerprint/ecdsa-sha2-nistp384", value:"QE5PVFNFVEA=");

     if ( ! get_kb_item("SSH/KnownFingerprint/ecdsa-sha2-nistp521"))
       set_kb_item(name:"SSH/KnownFingerprint/ecdsa-sha2-nistp521", value:"QE5PVFNFVEA=");

     if ( ! get_kb_item("SSH/KnownFingerprint/ssh-ed25519"))
       set_kb_item(name:"SSH/KnownFingerprint/ssh-ed25519", value:"QE5PVFNFVEA=");
   }
  }

}

ssh_settings = ssh_settings_get_settings();
insert_ssh_settings_kb(ssh_settings:ssh_settings);
ssh_settings_known_host();
