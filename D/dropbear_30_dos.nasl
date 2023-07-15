#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(21023);
  script_version("1.18");

  script_cve_id("CVE-2006-1206");
  script_bugtraq_id(17024);

  script_name(english:"Dropbear SSH Authorization-pending Connection Saturation DoS");
  script_summary(english:"Checks for authorization pending connection limit in Dropbear SSH server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is susceptible to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Dropbear, a small, open source SSH server.

The version of Dropbear installed on the remote host, by default, has 
a limit of 30 connections in the authorization-pending state; 
subsequent connections are closed immediately. This issue can be 
exploited trivially by an unauthenticated attacker to deny service to 
legitimate users." );
 script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/426999/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2006/Mar/222" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Dropbear 0.48 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/08");
 script_cvs_date("Date: 2018/11/15 20:50:21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:matt_johnston:dropbear_ssh_server");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006-2018 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}


port = get_kb_item("Services/ssh");
if (!port) port = 22;
if (!get_port_state(port)) exit(0, "Port "+port+" is closed.");


# Make sure it's Dropbear.
banner = get_kb_item("SSH/banner/" + port);
if (!banner) exit(1, "No SSH banner on port "+port+".");
if ("dropbear" >!< banner) exit(0, "The SSH server on port "+port+" is not Dropbear.");


if (ereg(pattern:"dropbear_0\.([0-3]|4[0-7])", string:banner))
    security_warning(port);
else
  exit(0, "The remote service on port "+port+" is unaffected (newer than dropbear 0.47).");
