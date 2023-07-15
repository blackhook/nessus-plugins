#
# (C) Tenable Network Security, Inc.
#

################
# References
################
#
# http://www.securityfocus.com/bid/158/
# Exceed Denial of Service Vulnerability
# CVE-1999-1196


include('compat.inc');

if(description)
{
  script_id(17296);
  script_version("1.21");

  script_cve_id("CVE-1999-1196");
  script_bugtraq_id(158);

  script_name(english:"Network Service Malformed Data Remote DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is potentially vulnerable to a denial of service attack." );
  script_set_attribute(attribute:"description", value:
"It appears to be possible to crash the remote service by sending it a few
kilobytes of random data. 

An attacker may use this flaw to make this service crash continuously,
preventing this service from working properly. It may also be possible 
to exploit this flaw to execute arbitrary code on this host." );
  script_set_attribute(attribute:"solution", value:
"Upgrade your software or contact your vendor to inform them of this 
potential vulnerability." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on manual analysis of potential vulnerability.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/08");
  script_set_attribute(attribute:"vuln_publication_date", value: "1999/04/27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  # Maybe we should set this to ACT_DESTRUCTIVE_ATTACK only?
  script_category(ACT_DENIAL);

  script_copyright(english:"This script is Copyright (C) 2005-2023 Tenable Network Security, Inc.");
  script_family(english: "Denial of Service");
  script_dependencies("find_service1.nasl", "find_service2.nasl");
  exit(0);
}

var ports = get_kb_list("Ports/tcp/*");
if (isnull(ports)) exit(0, 'No open TCP ports to check.');

var beurk = '';
for (var i = 0; i < 256; i ++)
  beurk = strcat(beurk, 
  raw_string(rand() % 256), raw_string(rand() % 256),
  raw_string(rand() % 256), raw_string(rand() % 256),
  raw_string(rand() % 256), raw_string(rand() % 256),
  raw_string(rand() % 256), raw_string(rand() % 256));
# 2 KB

var port, soc, report, soc_status;
var vuln_ports = [];

foreach port (keys(ports))
{
  port = int(port - "Ports/tcp/");
  dbg::detailed_log(lvl: 2, msg: 'Testing port: ' + port);
  soc = open_sock_tcp(port);
  if (soc)
  {
    send(socket: soc, data: beurk);
    close(soc);
    # giving a little time to the service to react to the DoS packet
    sleep(1);
    soc_status = service_is_dead(port: port, exit: 0, try: 3);
    # if soc_status is -1 it means opening the socket timedout, increase Recv timeout
    dbg::detailed_log(lvl: 2, msg: 'For port ' + port + ' service_is_dead() returned: ' + soc_status);
    if ( soc_status > 0)
    {
      append_element(value:port, var:vuln_ports);
    }
  }
}

if (!empty_or_null(vuln_ports))
{
  foreach port(vuln_ports)
  {
    report = 'The service running on port ' + port + ' is potentially vulnerable to DoS attacks.';
    security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  }
}
else 
  exit(0, 'The remote host is not affected.');
