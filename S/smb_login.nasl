#TRUSTED 71c9437b405f3266dbd4f3799175a1f71062b5c7fb782ee0ce51f692bcfcd6fa7dca4034106ca0f1f8cbf8ace88f79d68a54ad0e0974ada98fa68bc4a4e5878df213f82453973ca5e27ea6dcba08a3aad6f7ed2262a66103db59e88ed657d81b6942db3ccf7bfe94b458061d0934b6db7519b6d39b75262025a009dcd29879607abe360b0211a4c175504982ef8ab7c4e255869412e7351f48afede6e381a0bd4191c947db04cb2173858fa5f8b1306748ebc8a8610d328b1247fe113e405b42cd02bd3bc069957345cce37308a2c223211586c45b8d6ddc1ce700af1b9f59de0984d2e3bf09b2a37fe38f58e876a5cfc2e86e1284b1ec02b9bb9eb14169e6dc271a9594e0da48a8679dde8d98224d2283a1cc2d30483e897a420afecb5b5e36a3b05c8701a148a431104ce5f5d8cbf5e3a279c3cc9197fafbbbcd5325ef16d58661625ba9d379f02c7715ab3ed0a53167f094f4bc7e468c6071860d4f12557a936c01acd1fb80663aeb21ce49c1f536d257dc94d6dfcb5bc63189cc3ad16bf9be2a9149f2abde8a027880f436f523a94ea61fdf799e99ad866fbdefc620b77337b9d0382f9f0d388940393e13eae4ace272b3980b43ac52d2d4425d42cb05961102dd8859a767ef9bf2a3f17f9b2669637c14363f6626d44380cace0ee47b72f750dee9a1cbf55a59c090356c3ceede71dc5c095b2334620191ee1ef0cc78fb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10394);
  script_version("1.172");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/27");

  script_name(english:"Microsoft Windows SMB Log In Possible");
  script_summary(english:"Attempts to log into the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to log into the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Microsoft Windows operating system or
Samba, a CIFS/SMB server for Unix. It was possible to log into it
using one of the following accounts :

- Guest account
- Supplied credentials");
  # https://support.microsoft.com/en-us/help/143474/restricting-information-available-to-anonymous-logon-users
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c2589f6");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/246261");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2000-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_start_server_svc.nbin", "global_settings.nasl", "kerberos.nasl", "netbios_name_get.nasl", "cifs445.nasl", "logins.nasl", "smb_nativelanman.nasl");
  script_require_keys("SMB/name", "SMB/transport");
  script_require_ports(139, 445, "/tmp/settings");

  exit(0);
}

include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("lcx.inc");

# Plugin is run by the local Windows Nessus Agent
if (get_kb_item("nessus/product/agent"))
{
  # Note: some Windows credentialed plugins call:
  # script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  # Here we manually set the KBs
  set_kb_item(name:"SMB/login", value:"");
  set_kb_item(name:"SMB/password", value:"");

  # Set Local checks KB items
  set_kb_item(name:"Host/windows_local_checks", value:TRUE);
  set_kb_item(name:"Host/local_checks_enabled", value:TRUE);

  # set domain/workgroup if known
  # set_kb_item(name:"SMB/domain", value:"");
  exit(0);
}

global_var session_is_admin, port;

##
# kdc will only be present for credentials where the user has
# specified kerberos authentication on scanners >= nessus 6.0
##
function login(lg, pw, dom, lm, ntlm, kdc)
{
  local_var r, r2, soc;

  session_is_admin = 0;

  if (kdc)
  {
    replace_kb_item(name:"Kerberos/SMB/kdc_use_tcp", value:kdc["use_tcp"]);
    replace_kb_item(name:"SMB/only_use_kerberos", value:TRUE);
    replace_kb_item(name:"KerberosAuth/enabled", value:TRUE);
    # used by open_sock_ex() (nessus >= 6)
    replace_kb_item(name:"Secret/SMB/kdc_hostname", value:kdc["host"]);
    replace_kb_item(name:"Secret/SMB/kdc_port", value:int(kdc["port"]));
    # used by open_sock_kdc() (nessus < 6)
    replace_kb_item(name:"Secret/kdc_hostname", value:kdc["host"]);
    replace_kb_item(name:"Secret/kdc_port", value:int(kdc["port"]));
    replace_kb_item(name:"Secret/kdc_use_tcp", value:int(kdc["use_tcp"]));
  }
  # Use latest version of SMB that Nessus and host share (likely SMB 2.002)
  if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
  r = NetUseAdd(login:lg, password:pw, domain:dom, lm_hash:lm, ntlm_hash:ntlm, share:"IPC$");
  if (r == 1)
  {
    NetUseDel(close:FALSE);
    r2 = NetUseAdd(share:"ADMIN$");
    if (r2 == 1) session_is_admin = TRUE;
  }
  NetUseDel();

  # If that fails, fallback to SMB1
  if (r != 1)
  {
    if (!smb_session_init(smb2:FALSE)) audit(AUDIT_FN_FAIL, 'smb_session_init');
    r = NetUseAdd(login:lg, password:pw, domain:dom, lm_hash:lm, ntlm_hash:ntlm, share:"IPC$");
    if (r == 1)
    {
      NetUseDel(close:FALSE);
      r2 = NetUseAdd(share:"ADMIN$");
      if (r2 == 1) session_is_admin = TRUE;
    }
    NetUseDel();
  }

  if (kdc)
  {
    # this needs to be deleted after each authentication attempt to avoid having stale KDC data in the KB
    # (e.g. 1st credentials attempt kerberos auth, 2nd credentials do not attempt kerberos auth).
    # if kerberos auth succeeds, this data will be saved in the KB permanently below where SMB/login et al are saved
    rm_kb_item(name:"Kerberos/SMB/kdc_use_tcp");
    rm_kb_item(name:"SMB/only_use_kerberos");
    rm_kb_item(name:"KerberosAuth/enabled");
    rm_kb_item(name:"Secret/SMB/kdc_hostname");
    rm_kb_item(name:"Secret/SMB/kdc_post");
    rm_kb_item(name:"Secret/kdc_hostname");
    rm_kb_item(name:"Secret/kdc_port");
    rm_kb_item(name:"Secret/kdc_use_tcp");
  }

  if (r == 1)
  {
    if (session_is_admin) replace_kb_item(name:"SMB/use_smb2", value:session_is_smb2());
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

login_has_been_supplied = 0;
port = kb_smb_transport();
name = kb_smb_name();

# the port scanner ran and determined the SMB transport port isn't open
if (get_kb_item("Host/scanned") && !get_port_state(port))
{
  audit(AUDIT_PORT_CLOSED, port);
}

soc = open_sock_tcp(port);
if (!soc)
{
  audit(AUDIT_SOCK_FAIL, port);
}
close(soc);

##
# Get all of the required parameters from the kb and
# set them to an array for access.
##
for (i = 0; TRUE; i ++)
{
  l = get_kb_item("SMB/login_filled/" + i);
  if (l)
  {
    l = ereg_replace(pattern:"([^ ]*) *$", string:l, replace:"\1");
  }

  p = get_kb_item("SMB/password_filled/" + i);
  if (p)
  {
    p = ereg_replace(pattern:"([^ ]*) *$", string:p, replace:"\1");
  }
  else
  {
    p = "";
  }

  d = get_kb_item("SMB/domain_filled/" + i);
  if (d)
  {
    d = ereg_replace(pattern:"([^ ]*) *$", string:d, replace:"\1");
  }

  t = get_kb_item("SMB/password_type_filled/" + i);

  cred_type = get_kb_item("SMB/cred_type" + i);

  if (!get_kb_item("Kerberos/global"))
  {
    kdc_host = get_kb_item("SMB/kdc_hostname_filled/" + i);
    kdc_port = get_kb_item("SMB/kdc_port_filled/" + i);
    kdc_use_tcp = get_kb_item("SMB/kdc_use_tcp_filled/" + i);
  }

  if (l)
  {
    login_has_been_supplied ++;
    logins[i] = l;
    passwords[i] = p;
    domains[i] = d;
    password_types[i] = t;
    cred_types[i] = cred_type;
    if (kdc_host && kdc_port)
    {
      kdc_info[i] = make_array(
        "host", kdc_host,
        "port", int(kdc_port),
        "use_tcp", kdc_use_tcp
     );
    }
  }
  else break;
}

smb_domain = string(get_kb_item("SMB/workgroup"));

if (smb_domain)
{
  smb_domain = ereg_replace(pattern:"([^ ]*) *$", string:smb_domain, replace:"\1");
}

##
# Start testing access levels for SMB service
##
hole = 0;
rand_lg = rand_str(length:8, charset:"abcdefghijklmnopqrstuvwxyz");
rand_pw = rand_str(length:8);

# Test Null sessions
if (login(lg:NULL, pw:NULL, dom:NULL))
{
  null_session = TRUE;
}
else
  null_session = FALSE;

# Test administrator Null Login
if (!supplied_logins_only)
{
  if (login(lg:"administrator", pw:NULL, dom:NULL) && !session_is_guest())
  {
    admin_no_pw = TRUE;
  }
  else
  {
    admin_no_pw = FALSE;
  }

  # Test open to anyone login settings
  if (login(lg:rand_lg, pw:rand_pw, dom:NULL))
  {
    any_login = TRUE;
    set_kb_item(name:"SMB/any_login", value:TRUE);
  }
  else
  {
    any_login = FALSE;
  }
}

##
# Start testing supplied creds
##
supplied_login_is_correct = FALSE;
working_login = NULL;
working_password = NULL;
working_password_type = NULL;
working_kdc = NULL;
working_domain = NULL;
working_cred_type = NULL;
login_cred_type = NULL;

valid_logins = make_list();
valid_passwords = make_list();

loginFails = make_nested_array(); # for reporting failed login attempts

for (i = 0; logins[i] && !supplied_login_is_correct; i++)
{
  logged_in = 0;
  user_login = logins[i];
  k_password = user_password = passwords[i];
  user_domain = domains[i];
  p_type = password_types[i];
  kdc = kdc_info[i];

  if (p_type == 0)
  {
    lm = ntlm = NULL;
  }
  if (p_type == 1)
  {
    lm = hex2raw2(s:tolower(user_password));
    ntlm = user_password = NULL;
  }
  else if (p_type == 2)
  {
    ntlm = hex2raw2(s:tolower(user_password));
    lm = user_password = NULL;
  }

  # user domain
  if (login(lg:user_login, pw:user_password, dom:user_domain, lm:lm, ntlm:ntlm, kdc:kdc) && !session_is_guest())
  {
    logged_in ++;
    if (session_is_admin) supplied_login_is_correct = TRUE;
    if (!working_login || session_is_admin)
    {
      working_login = user_login;
      if (isnull(user_password))
      {
        if (!isnull(lm)) user_password = hexstr(lm);
        else if (!isnull(ntlm)) user_password = hexstr(ntlm);
      }

      working_password = user_password;
      working_password_type = p_type;
      working_kdc = kdc;
      working_domain = user_domain;
      working_cred_type = cred_types[i];
    }
  }
  else
  {
    if (tolower(user_domain) != tolower(smb_domain))
    {
      # smb domain
      if (login(lg:user_login, pw:user_password, dom:smb_domain, lm:lm, ntlm:ntlm, kdc:kdc) && !session_is_guest())
      {
        logged_in ++;
        if (session_is_admin) supplied_login_is_correct = TRUE;
        if (!working_login || session_is_admin)
        {
          working_login = user_login;
          if (isnull(user_password))
          {
            if (!isnull(lm)) user_password = hexstr(lm);
            else if (!isnull(ntlm)) user_password = hexstr(ntlm);
          }
          working_password = user_password;
          working_password_type = p_type;
          working_domain = smb_domain;
          working_cred_type = cred_types[i];
        }
      }
    }

    if (!logged_in)
    {
      # no domain
      if (login(lg:user_login, pw:user_password, dom:NULL, lm:lm, ntlm:ntlm, kdc:kdc) && !session_is_guest())
      {
        logged_in++;
        if (session_is_admin) supplied_login_is_correct = TRUE;
        if (!working_login || session_is_admin)
        {
          working_login = user_login;
          if (isnull(user_password))
          {
            if (!isnull(lm)) user_password = hexstr(lm);
            else if (!isnull(ntlm)) user_password = hexstr(ntlm);
          }
          working_password = user_password;
          working_password_type = p_type;
          working_domain = NULL;
          working_cred_type = cred_types[i];
        }
        smb_domain = NULL;
      }
    }

    if (!logged_in)
    {
      thisUser = '';
      if (!empty_or_null(user_domain))
        thisUser += user_domain + "\";
      thisUser += user_login;

      if (!empty(thisUser))
        loginFails[thisUser] = 'Failed to authenticate using the supplied credentials.';
    }
  }
}

if (working_login)
{
  supplied_login_is_correct = TRUE;
  user_login = working_login;
  user_password = working_password;
  user_password_type = working_password_type;
  user_kdc = working_kdc;
  smb_domain = working_domain;
  login_cred_type = working_cred_type;
  replace_kb_item(name:"Host/Auth/SMB/"+port+"/Success", value:working_login);
  rm_kb_item(name:"Host/Auth/SMB/"+port+"/"+SCRIPT_NAME+"/Problem");
  rm_kb_item(name:"Host/Auth/SMB/"+port+"/Failure");
  lcx::log_auth_success(proto:lcx::PROTO_SMB, port:port, user:user_login,
    clear_failures:TRUE);
}
else
{
  kb_pre = "Host/Auth/SMB/"+port;
  set_kb_item(name:kb_pre+"/Failure", value:TRUE);
  foreach var username (keys(loginFails))
  {
    lcx::log_issue(type:lcx::ISSUES_AUTH, msg:loginFails[username],
      port:port, proto:lcx::PROTO_SMB, user:username);
  }
  if (!supplied_login_is_correct && !admin_no_pw && login_has_been_supplied)
    lcx::log_issue(type:lcx::ISSUES_SVC, proto:lcx::PROTO_SMB, msg:
      'It was not possible to log into the remote host via smb ' +
      '(invalid credentials).', port:port);
}

report = '';

if (null_session || supplied_login_is_correct || admin_no_pw || any_login)
{
  if ( null_session != 0 )
  {
    set_kb_item(name:"SMB/null_session_suspected", value:TRUE);
    if (report_paranoia >= 2)
    {
      report += '- NULL sessions may be enabled on the remote host.\n';
    }
  }

  if (supplied_login_is_correct)
  {
    if (!user_password) user_password = "";

    set_kb_item(name:"SMB/login", value:user_login);
    set_kb_item(name:"SMB/password", value:user_password);
    set_kb_item(name:"SMB/password_type", value:user_password_type);
    if (!isnull(user_kdc))
    {
      replace_kb_item(name:"Secret/SMB/kdc_hostname",  value:user_kdc["host"]);
      replace_kb_item(name:"Secret/SMB/kdc_port",      value:int(user_kdc["port"]));
      replace_kb_item(name:"Secret/kdc_hostname",      value:kdc["host"]);
      replace_kb_item(name:"Secret/kdc_port",          value:int(kdc["port"]));
      replace_kb_item(name:"Secret/kdc_use_tcp",       value:int(kdc["use_tcp"]));
      replace_kb_item(name:"Kerberos/SMB/kdc_use_tcp", value:user_kdc["use_tcp"]);
      replace_kb_item(name:"KerberosAuth/enabled",     value:TRUE);
      replace_kb_item(name:"SMB/only_use_kerberos",    value:TRUE);
    }
    if (smb_domain != NULL)
    {
      set_kb_item(name:"SMB/domain", value:smb_domain);
      report += '- The SMB tests will be done as ' + smb_domain + '\\' + user_login + '/******\n';
    }
    else
      report += '- The SMB tests will be done as ' + user_login + '/******\n';

    if(session_is_admin)
      replace_kb_item(name:"Host/Auth/SMB/" + port + "/MaxPrivs", value:1);
  }

  # https://discussions.nessus.org/message/9562#9562 -- Apple's Time Capsule accepts any login with a
  # blank password
  if (admin_no_pw && !any_login && !login(lg:rand_str(length:8), pw:""))
  {
    set_kb_item(name:"SMB/blank_admin_password", value:TRUE);
    report += '- The \'administrator\' account has no password set.\n';
    hole = 1;
    if (!supplied_login_is_correct)
    {
      set_kb_item(name:"SMB/login", value:"administrator");
      set_kb_item(name:"SMB/password", value:"");
      set_kb_item(name:"SMB/domain", value:"");
    }
  }

  if (any_login)
  {
    set_kb_item(name:"SMB/guest_enabled", value:TRUE);
    report += '- Remote users are authenticated as \'Guest\'.\n';
    if (!supplied_login_is_correct && !admin_no_pw)
    {
      set_kb_item(name:"SMB/login", value:rand_lg);
      set_kb_item(name:"SMB/password", value:rand_pw);
      set_kb_item(name:"SMB/domain", value:"");
    }
  }

  if (null_session)
  {
    if (!supplied_login_is_correct && !admin_no_pw && !any_login)
    {
      set_kb_item(name:"SMB/login", value:"");
      set_kb_item(name:"SMB/password", value:"");
      set_kb_item(name:"SMB/domain", value:"");
    }
  }

  if (supplied_login_is_correct || admin_no_pw)
  {
    if (!get_kb_item("SMB/not_windows"))
    {
      set_kb_item(name:"Host/windows_local_checks", value:TRUE);
      set_kb_item(name:"Host/local_checks_enabled", value:TRUE);
    }

    kb_dom = get_kb_item("SMB/domain");
    kb_lg  = get_kb_item("SMB/login");
    if (isnull(kb_dom)) kb_dom = get_host_ip();
    login_used = kb_dom + '\\' + kb_lg;

    set_kb_item(name:"HostLevelChecks/smb_login", value:login_used);
    if (!empty_or_null(login_cred_type))
    {
      replace_kb_item(name:"HostLevelChecks/cred_type", value:login_cred_type);
    }
    
    if (defined_func("report_xml_tag"))
    {
      report_xml_tag(tag:"local-checks-proto", value:"smb");
      report_xml_tag(tag:"smb-login-used",     value:login_used);
    }
  }

  if (!null_session || (null_session && (report_paranoia >= 2)))
  {
    security_note(port:port, extra:report);
  }
  else
  {
    audit(AUDIT_POTENTIAL_VULN, 'scanner was able to connect to a share with no username or password, but did not 
    attempt to bind. A NULL session may be possible but this');
    # The scanner was able to connect to a share with no username or password, but did not attempt to bind. A NULL 
    # session may be possible but this install is potentially affected and therefore is only reported if 
    # 'Report Paranoia' is set to 'Paranoid'.
  }
}
else
{
  if (isnull(get_kb_item('SMB/login_filled/0'))) audit(AUDIT_MISSING_CREDENTIALS, "Windows");
  else exit(0, "Failed to connect to the SMB service. Could not authenticate with the supplied credentials.");
}
