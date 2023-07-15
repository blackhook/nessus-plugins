#TRUSTED 720906e9a1925188783d02ed950966bcccec1d7c115cd27bd4bfcc68aaa9253c95e0d94236a1813971686dfce6a7c0b7fc1f85c96b78639a3516f2116d70760fab6ca514ff270eeb9e98f7562288db4fd4f492213ebc7783ffe8c51cd95f8afc718211858afd5c503fb4c8ba4278268112238431742c80dd9e5bea7e68a52c692ea3e99ff15582045fd5b71d9c56f97adefaa2b00cf2e9c7eb4216c1ce95a0d24f6fe2fa705ffb7e29d44c4228532056535f9b8a11ad9d059669a13de5a7aab1eb908f4822377d6a9ab1dc07cd3c2754c1b14ce8d509dbf5fcba34e3f9db83756a39ce39ef154708da2d654c48ac0e6a429dbf38e797413abb07b686ff2bb088fa41016da72a1ea3cb36d8dd7ef5321fa2f1a58d5eee672d3667f4377b2b07df8bf866a469f2275ef5aa5f9f6a70d399d9c3b458a0cc9415e92ec675eb5ac4f9a962d541dd81642d199bfd2b29930695abd652e12e51fde96662a548eda30c1c4ba8da422f5d7b579580f47a299e3be8607fa2950141c244072f42d7d9f70259b1afff62151931a7c0f22f1f870c41928b7817c1802964a98b9554deda856e3570d6f882ef58b391deb9179156e3c18ee5942b93e5871435518ac15bc906ca162aa0f6353129236619231690be27ea671e8bbd74e913d1a7f8f0b9670d6c11c0ca61cd7dc02b762b079310aaf45e7a05e02458da173eb4d330fc4db1431bfcaa
#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(72663);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"SFTP Supported");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service supports SFTP.");
  script_set_attribute(attribute:"description", value:
"The remote SSH service supports the SFTP subsystem. SFTP is a protocol
for generalized file access, file transfer, and file management
functionalities, typically over SSH.

Note that valid credentials are required to determine if SFTP is
supported and also that SFTP support can be enabled selectively for
certain accounts.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/SSH_File_Transfer_Protocol");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this facility agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_settings.nasl", "ssh_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("ssh_fxp_func.inc");



enable_ssh_wrappers();

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);


if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


# Generate a list of accounts to check.
i = 0;
logins      = make_array();
passwords   = make_array();
passphrases = make_array();
privs       = make_array();
pubs        = make_array();
certs       = make_array();
realms      = make_array();

# - anonymous
logins[i]    = "anonymous";
passwords[i] = SCRIPT_NAME + '@nessus.org';
i++;

# - guest
logins[i]    = "guest";
passwords[i] = SCRIPT_NAME + '@nessus.org';
i++;

# - credentials supplied in the scan policy.
kb_login = kb_ssh_login();
if (strlen(kb_login))
{
  found = FALSE;
  for (k=0; k<i; k++)
  {
    if (kb_login == logins[k])
    {
      found = TRUE;
      break;
    }
  }
  if (!found)
  {
    logins[i]      = kb_login;
    passwords[i]   = kb_ssh_password();
    passphrases[i] = kb_ssh_passphrase();
    privs[i]       = kb_ssh_privatekey();
    pubs[i]        = kb_ssh_publickey();
    certs[i]       = kb_ssh_certificate();
    realms[i]      = kb_ssh_realm();
    i++;
  }
}

if (get_kb_item("Secret/SSH/0/login"))
{
  for (j=0; TRUE; j++)
  {
    login = get_kb_item("Secret/SSH/"+j+"/login");
    if (isnull(login)) break;
    pass = get_kb_item("Secret/SSH/"+j+"/password");

    found = FALSE;
    for (k=0; k<i; k++)
    {
      if (login == logins[k])
      {
        found = TRUE;
        break;
      }
    }

    if (!found)
    {
      logins[i] = login;
      passwords[i] = get_kb_item("Secret/SSH/", j, "/password");
      passphrases[i] = get_kb_item("Secret/SSH/", j, "/passphrase");
      privs[i] = kb_ssh_alt_privatekey(j);
      certs[i] = get_kb_item("Secret/SSH/", j, "/certificate");
      realms[i] = get_kb_item("Kerberos/SSH/", j, "/realm");
      i++;
    }
  }
}
n = i;


# Test each account.
dir = "/";
max_files = 10;
want_reply = (report_paranoia == 0);

checked_logins = make_list();
working_logins = make_list();

report = '';
for (i=0; i<n; i++)
{
  checked_logins = make_list(checked_logins, logins[i]);

  rc = ssh_fxp_open_connection(
    port       : port,
    login      : logins[i],
    password   : passwords[i],
    passphrase : passphrases[i],
    priv       : privs[i],
    pub        : pubs[i],
    cert       : certs[i],
    realm      : realms[i],
    want_reply : want_reply
  );
  if (rc)
  {
    set_kb_item(name:"SSH/"+port+"/sftp/login", value:logins[i]);
    working_logins = make_list(working_logins, logins[i]);

    if (report_verbosity > 0)
    {
      if (strlen(report) == 0)
      {
        report = '\n' + 'Nessus was able to access the SFTP service using the following' +
                 '\n' + 'account :' +
                 '\n' +
                 '\n' + '  ' + logins[i];

        listing = ssh_fxp_get_listing(dir:dir, max_files:max_files);
        if (!isnull(listing))
        {
          report += '\n' +
                    '\n' + 'And it was able to collect the following listing of \'' + dir + '\' :' +
                    '\n';
          foreach file (sort(keys(listing['files'])))
          {
            report += '\n' + '  ' + listing['files'][file];
          }
          if (listing['truncated'])
          {
            report += '\n' +
                      '\n' + 'Note that this listing is incomplete and limited to ' + max_files + ' entries.  To' +
                      '\n' + 'list all files, set the \'Report verbosity\' preference in the scan' +
                      '\n' + 'policy to \'Verbose\' and re-scan.' +
                      '\n';
          }
        }
      }
    }

    ssh_fxp_close_connection();
    if (!thorough_tests) break;
  }
}
if (max_index(working_logins) == 0)
{
  ssh_close_connection();
  err_msg = "The SSH service listening on port "+port+" does not support SFTP access for the login";
  if (max_index(checked_logins) > 1) err_msg += "s";
  err_msg += " '" + join(checked_logins, sep:"' / '") + "'.";
  exit(0, err_msg);
}

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
