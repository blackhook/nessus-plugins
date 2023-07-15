#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155962);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/06");

  script_cve_id("CVE-2021-41349", "CVE-2021-42305", "CVE-2021-42321");
  script_xref(name:"IAVA", value:"2021-A-0543-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/01");
  script_xref(name:"MSKB", value:"5007409");
  script_xref(name:"MSFT", value:"MS21-5007409");

  script_name(english:"Security Updates for Exchange (November 2021) (Remote)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A session spoofing vulnerability exists. An attacker can
    exploit this to perform actions with the privileges of
    another user. (CVE-2021-41349, CVE-2021-42305)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-42321)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5007409");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5007409 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42321");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Exchange Server ChainedSerializationBinder RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("exchange_detect.nbin");
  script_require_keys("installed_sw/Exchange Server");

  exit(0);
}

include('http.inc');
include('vcf.inc');

var port = get_http_port(default:80);
var app = 'Exchange Server';
var app_info = vcf::get_app_info(app:app, port:port);

if (report_paranoia < 2)
  vcf::check_granularity(app_info:app_info, sig_segments:4);

var constraints = [
 {'min_version' : '15.0.1497', 'fixed_version':'15.0.1497.26'},
 {'min_version' : '15.1.2375', 'fixed_version':'15.1.2375.17'},
 {'min_version' : '15.1.2308', 'fixed_version':'15.1.2308.20'},
 {'min_version' : '15.2.986', 'fixed_version':'15.2.986.14'},
 {'min_version' : '15.2.922', 'fixed_version':'15.2.922.19'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
