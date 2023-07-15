#
# (C) Tenable Network Security, Inc.
#

account = "netscreen";
password = "<<< %s(un='%s') = %u";

include("compat.inc");

if (description)
{
  script_id(87601);
  script_version("1.10");
  script_cvs_date("Date: 2018/07/27 18:38:14");

  script_cve_id("CVE-2015-7755");
  script_bugtraq_id(79626);
  script_xref(name:"JSA", value:"JSA10713");
  script_xref(name:"CERT", value:"640184");

  script_name(english:"Juniper ScreenOS SSH / Telnet Authentication Backdoor");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"An account on the remote host uses a known password.");
  script_set_attribute(attribute:"description", value:
"The account 'netscreen' on the remote host has the password
'" + password +"', a known backdoor password. The affected
devices are firewalls and VPN gateways. A remote attacker can exploit
this vulnerability to gain administrative access and monitor network
traffic, deny network access, and alter device and firewall
configurations.");
  # https://forums.juniper.net/t5/Security-Incident-Response/Important-Announcement-about-ScreenOS/ba-p/285554
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6cfb32d");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10713");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Juniper ScreenOS 6.2.0r19 / 6.3.0r21 or later.
Alternatively, apply the appropriate patch referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:T/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Default Unix Accounts");

  script_copyright(english:"This script is Copyright (C) 2015-2018 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl", "account_check.nasl", "telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23, "Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("default_account.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

affected = FALSE;
ssh_ports = get_service_port_list(svc: "ssh", default:22);
foreach port (ssh_ports)
{
  ssh_port = check_account(login:account, password:password, 
                           cmd:"get clock", 
                           cmd_regex:"The Network Time Protocol", 
                           nosh:TRUE, noexec:TRUE, check_telnet:TRUE, 
                           port:port, svc:"ssh");
  if (ssh_port)
  {
    affected = TRUE;
    security_report_v4(port:telnet_port, severity:SECURITY_HOLE, extra:default_account_report());
  }
}
if(affected) exit(0);

telnet_ports = get_service_port_list(svc: "telnet", default:23);
foreach port (telnet_ports)
{
  telnet_port = check_account(login:account, password:password, 
                              cmd:"get clock", 
                              cmd_regex:"The Network Time Protocol", 
                              nosh:TRUE, noexec:TRUE, check_telnet:TRUE, 
                              port:port, svc:"telnet");
  if (telnet_port)
  {
    affected = TRUE;
    security_report_v4(port:telnet_port, severity:SECURITY_HOLE, extra:default_account_report());
  }
}
if(!affected) audit(AUDIT_HOST_NOT, "affected");