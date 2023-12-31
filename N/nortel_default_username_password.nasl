#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15715);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Nortel Multiple Default Accounts");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to log into the remote switch using default
credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote host by using a default set of
credentials. An attacker may use these to gain access to the remote
host.

These credentials are commonly found on Nortel Accelar routing
switches.");
  script_set_attribute(attribute:"solution", value:
"Set a strong password for these accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:X/RC:X");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2004-2022 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "os_fingerprint.nasl", "ssh_detect.nasl", "account_check.nasl");
  script_exclude_keys("global_settings/supplied_logins_only", "login/unix/auth/broken", "login/auth/broken");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include("global_settings.inc");

checking_default_account_dont_report = TRUE;

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
get_kb_item_or_exit("SSH/banner/" + port);

if (!thorough_tests) audit(AUDIT_THOROUGH);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if (
  get_kb_item("login/unix/auth/broken") || 
  get_kb_item("login/auth/broken")
) exit(0, "It is not possible to determine if remote accounts are valid on this host.");

credentials = make_array(
  "12", "12",
  "13", "13",
  "ro", "ro",
  "rw", "rw",
  "rwa", "rwa"
);

working_login = NULL;

foreach key ( keys(credentials) )
{
  _ssh_socket = open_sock_tcp(port);
  if ( ! _ssh_socket ) audit(AUDIT_SOCK_FAIL, port);

  ret = ssh_login(login:key, password:credentials[key]);
  ssh_close_connection();

  if ( ret == 0 ) working_login += '\n  ' + key + '/' + credentials[key];
}

if ( !isnull(working_login) )
{
  if (report_verbosity > 0)
  {
    report = '\n' + 'The following credentials have been tested successfully :' +
             '\n' + 
             working_login +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT, "affected");
