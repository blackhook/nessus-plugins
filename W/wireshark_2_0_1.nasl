#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87825);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id(
    "CVE-2015-8711",
    "CVE-2015-8718",
    "CVE-2015-8720",
    "CVE-2015-8721",
    "CVE-2015-8722",
    "CVE-2015-8723",
    "CVE-2015-8724",
    "CVE-2015-8725",
    "CVE-2015-8726",
    "CVE-2015-8727",
    "CVE-2015-8728",
    "CVE-2015-8729",
    "CVE-2015-8730",
    "CVE-2015-8731",
    "CVE-2015-8732",
    "CVE-2015-8733",
    "CVE-2015-8734",
    "CVE-2015-8735",
    "CVE-2015-8736",
    "CVE-2015-8737",
    "CVE-2015-8738",
    "CVE-2015-8739",
    "CVE-2015-8740",
    "CVE-2015-8741",
    "CVE-2015-8742"
  );
  script_xref(name:"EDB-ID", value:"38993");
  script_xref(name:"EDB-ID", value:"38994");
  script_xref(name:"EDB-ID", value:"38995");
  script_xref(name:"EDB-ID", value:"38996");
  script_xref(name:"EDB-ID", value:"38997");
  script_xref(name:"EDB-ID", value:"38998");
  script_xref(name:"EDB-ID", value:"38999");
  script_xref(name:"EDB-ID", value:"39000");
  script_xref(name:"EDB-ID", value:"39001");
  script_xref(name:"EDB-ID", value:"39002");
  script_xref(name:"EDB-ID", value:"39003");
  script_xref(name:"EDB-ID", value:"39004");
  script_xref(name:"EDB-ID", value:"39005");
  script_xref(name:"EDB-ID", value:"39006");
  script_xref(name:"EDB-ID", value:"39076");
  script_xref(name:"EDB-ID", value:"39077");

  script_name(english:"Wireshark 2.0.0 Multiple DoS");
  script_summary(english:"Checks the version of Wireshark.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Wireshark installed on the remote Windows host is
2.0.0. It is, therefore, affected by multiple denial of service
vulnerabilities in the following components :

  - 802.11 dissector
  - ANSI A dissector
  - Ascend file parser
  - BER dissector
  - Bluetooth Attribute dissector
  - DIAMETER dissector
  - GSM A dissector
  - IPMI dissector
  - MP2T file parser
  - MS-WSP dissector
  - NBAP dissector
  - NLM dissector
  - NWP dissector
  - PPI dissector
  - RSL dissector
  - RSVP dissector
  - S7COMM dissector
  - SCTP dissector
  - Sniffer file parser
  - TDS dissector
  - VeriWave file parser
  - ZigBee ZCL dissector
  - zlib compression

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/docs/relnotes/wireshark-2.0.1.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Wireshark version 2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8742");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("installed_sw/Wireshark");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '2.0.0', 'max_version' : '2.0.0', 'fixed_version' : '2.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
