#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139802);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/26");

  script_cve_id("CVE-2018-15380");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvj95606");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvq24176");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190220-hyperflex-injection");

  script_name(english:"Cisco HyperFlex Software Command Injection (cisco-sa-20190220-hyperflex-injection)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco HyperFlex HX Data Platform is affected by a vulnerability in the cluster
service manager due to insufficient input validation. An unauthenticated, adjacent attacker can exploit this, by
connecting to the cluster service manager and injecting commands into the bound process, in order to execute commands as
the root user.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190220-hyperflex-injection
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3937ca2");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvj95606");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvq24176");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvj95606, CSCvq24176");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15380");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:hyperflex_hx_data_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_hyperflex_web_api_detect.nbin");
  script_require_keys("Host/OS/Cisco_HyperFlex_web_API");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

port = get_http_port(default:80);
app_info = vcf::get_app_info(app:'Cisco HyperFlex', port:port);

constraints = [
  {'fixed_version':'3.5.2g', 'fixed_display':'3.5(2g)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

