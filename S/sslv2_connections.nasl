#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(132634);
  script_version("1.1");
  script_cvs_date("Date: 2020/01/06");

  script_name(english:"Deprecated SSLv2 Connection Attempts");
  script_summary(english:"Displays information about SSLv2 connections attempted during a scan.");

  script_set_attribute(attribute:"synopsis", value:"Secure Connections, using a deprecated protocol were attempted as part of the scan");
  script_set_attribute(attribute:"description", value:"This plugin enumerates and reports any SSLv2 connections which 
  were attempted as part of a scan. This protocol has been deemed prohibited since 2011 because of security 
  vulnerabilities and most major ssl libraries such as openssl, nss, mbed and wolfssl do not provide this functionality
  in their latest versions. This protocol has been deprecated in Nessus 8.9 and later.");
  script_set_attribute(attribute:"solution", value:"N/A");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_END);

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  exit(0);
}

include('datetime.inc');
include('spad_log_func.inc');

sslv2_connections = get_kb_list('SSLv2/deprecated/*');
if (max_index(keys(sslv2_connections)) == 0)
  exit(0, 'No SSLv2 connections were attempted during the scan');

report = '\nNessus attempted the following SSLv2 connection(s) as part of this scan: \n\n'; 
foreach connection (keys(sslv2_connections)){
  parts = split(connection, sep:'/', keep:FALSE);
  report += 'Plugin ID: ' + parts[3] + '\n' +
            'Timestamp: ' + strftime('%Y-%m-%d %H:%M:%S', int(parts[2])) + '\n' +
            'Port: ' + sslv2_connections[connection] + '\n\n';
}

spad_log(message:report);

if(report_verbosity > 0)
  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
