#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55900);
  script_version("1.11");
  script_cvs_date("Date: 2019/10/04 16:48:26");

  script_name(english:"Remote Authentication Message Check");
  script_summary(english:"Attempts to log into the remote host with random credentials");

  script_set_attribute(attribute:"synopsis", value:
    "Check whether it is possible to determine if remote accounts are
    valid.");
  script_set_attribute(attribute:"description", value:
    "In order to avoid false positives, this plugin determines if the remote
    system accepts any kind of login.  Some SSH implementations claim that a
    login has been accepted when it has not.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2011-2019 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "ssh_detect.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}


#
# The script code starts here :
#
include("audit.inc");
include("default_account.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  if ( report_paranoia == 0 )
  {
    ssh_port = check_account(login:rand_str(length:8),
                             password:rand_str(length:8),
                             unix:TRUE,
                             check_mocana:TRUE,
                             port:port,
                             svc:"ssh");
    if(!ssh_port) ssh_port = check_account(login:rand_str(length:8),
                                           unix:TRUE,
                                           check_mocana:TRUE,
                                           port:port,
                                           svc:"ssh");
    if(ssh_port) set_kb_item(name:"login/unix/auth/broken", value:TRUE);
    affected = TRUE;
  }

  ssh_port = check_account(login:rand_str(length:8),
                           password:rand_str(length:8),
                           unix:FALSE,
                           check_mocana:TRUE,
                           port:port,
                           svc:"ssh");
  if(!ssh_port) ssh_port = check_account(login:rand_str(length:8),
                                         unix:FALSE,
                                         check_mocana:TRUE,
                                         port:port,
                                         svc:"ssh");
  if(ssh_port) set_kb_item(name:"login/auth/broken", value:TRUE);
  affected = TRUE;
}
if(affected) exit(0);

telnet_ports = get_service_port_list(svc: "telnet", default:23);
foreach port (telnet_ports)
{
  if ( report_paranoia == 0 )
  {
   telnet_port = check_account(login:rand_str(length:8),
                               password:rand_str(length:8),
                               unix:TRUE,
                               check_mocana:TRUE,
                               port:port,
                               svc:"telnet");
   if(!telnet_port) telnet_port = check_account(login:rand_str(length:8),
                                                unix:TRUE,
                                                check_mocana:TRUE,
                                                port:port,
                                                svc:"telnet");
   if(telnet_port) set_kb_item(name:"login/unix/auth/broken", value:TRUE);
   affected = TRUE;
  }

 telnet_port = check_account(login:rand_str(length:8),
                             password:rand_str(length:8),
                             unix:FALSE,
                             check_mocana:TRUE,
                             port:port,
                             svc:"telnet");
 if (!telnet_port) telnet_port = check_account(login:rand_str(length:8),
                                               unix:FALSE,
                                               check_mocana:TRUE,
                                               port:port,
                                               svc:"telnet");
 if(telnet_port) set_kb_item(name:"login/auth/broken", value:TRUE);
 affected = TRUE;
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");