#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51988);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Bind Shell Backdoor Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host may have been compromised.");
  script_set_attribute(attribute:"description", value:
"A shell is listening on the remote port without any authentication
being required. An attacker may use it by connecting to the remote
port and sending commands directly.");
  script_set_attribute(attribute:"solution", value:
"Verify if the remote host has been compromised, and reinstall the
system if necessary.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on manual analysis");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", "Services/wild_shell");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

ports = make_list();

wsports = get_kb_list("Services/wild_shell");
if (!empty_or_null(wsports))
{
  foreach port (wsports)
  {
    if (get_port_state(port))
      ports = make_list (ports, port);
  }
}

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  uports = get_kb_list("Services/unknown");
  if (!empty_or_null(uports))
  {
    foreach port (uports)
    {
      if (get_port_state(port) && service_is_unknown(port:port))
        ports = make_list (ports, port);
    }
  }
}

if(empty_or_null(ports)) exit(0, "No wild shell or unknown services to test against.");

ports = list_uniq(ports);

port = branch(ports);

# for each port try both normal and SSL communication
for (i = 0; i < 2; i++)
{
  soc = NULL;
  if (i == 0)
  {
    soc = open_sock_tcp(port);
  }
  else
  {
    soc = open_sock_tcp(port, transport:ENCAPS_TLSv1);
  }
 
  if (!soc)
  {
    continue;
  }

  cmds = make_list("id", "ipconfig");
  cmd_pats = make_array();
  cmd_pats['id'] = "uid=[0-9]+.*gid=[0-9]+.*";
  cmd_pats['ipconfig'] = "IP(v4)? Address. . .";

  flag = FALSE;

  foreach cmd (cmds)
  {
    request = cmd+'\n';

    send(socket:soc, data:request);
    r = recv(socket:soc, length:4096);
    if (empty_or_null(r)) continue;

    # Check for id command
    if ( ("uid=" >< r && egrep(pattern:cmd_pats[cmd], string:r)) ||
          (
            "Microsoft Windows" >< r &&
            "C:\">< r &&
            egrep(pattern:"\([c|C]\) (Copyright )?([0-9]+)", string:r) &&
            "Microsoft Corp" >< r
          )
      ) flag = TRUE;

    # Check for ipconfig command
    if ( "Windows IP Configuration" >< r &&
        egrep(pattern:cmd_pats[cmd], string:r)
      ) flag = TRUE;

    if (flag)
    {
      close(soc);
      if ((cmd == 'id' && data_protection::is_sanitize_username_enabled()) ||
          (cmd == 'ipconfig' && data_protection::is_sanitize_ipaddr_enabled()))
      {
        security_report_v4(port:port, severity:SECURITY_HOLE, extra:'Command execution of ' + cmd + ' successful.');
      }
      else
      {
        security_report_v4(port:port, severity:SECURITY_HOLE, cmd:cmd, request:request, output:r);
      }

      if (service_is_unknown(port:port))
      {
        register_service(port:port, proto: "wild_shell");
      }
      exit(0);
    }
  }
  close(soc);
}
audit(AUDIT_NOT_LISTEN, "A bind shell", port);
