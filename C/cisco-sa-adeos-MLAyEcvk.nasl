#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173975);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id("CVE-2023-20121");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd07345");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd41018");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe07088");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe07091");
  script_xref(name:"CISCO-SA", value:"cisco-sa-adeos-MLAyEcvk");

  script_name(english:"Cisco Prime Infrastructure Command Injection (cisco-sa-adeos-MLAyEcvk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Prime Infrastructure Software is affected by a command injection
vulnerability. This could allow an authenticated, local attacker to escape the restricted shell and gain root
privileges on the underlying operating system.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-adeos-MLAyEcvk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3aa66956");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd07345");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd07351");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd41018");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe07088");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe07091");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd07345, CSCwd07351, CSCwd41018, CSCwe07088,
CSCwe07091");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20121");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_infrastructure_detect.nbin");
  script_require_keys("installed_sw/Prime Infrastructure");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:'Prime Infrastructure', port:port, webapp:TRUE);
var constraints = [{'fixed_version':'3.10.4'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
