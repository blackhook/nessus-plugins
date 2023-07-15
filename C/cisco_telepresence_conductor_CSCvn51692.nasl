#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128176);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1679");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvn51692");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190206-rest-api-ssrf");

  script_name(english:"Cisco TelePresence Conductor REST API Server-Side Request Forgery Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Cisco TelePresence Conductor device is affected by a
command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, remote Cisco
TelePresence Conductor device is affected by a server-side request
forgery vulnerability which could allow an authenticated, remote 
attacker to trigger an HTTP request from an affected server to an 
arbitrary host.

Note that an attacker must be authenticated before the device is
exposed to this exploit.");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn339873");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190206-rest-api-ssrf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee44583b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version XC4.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1679");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_conductor");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_telepresence_conductor_detect.nbin");
  script_require_keys("Host/Cisco_TelePresence_Conductor/Version");

  exit(0);
}

include("vcf.inc");

app = "Cisco TelePresence Conductor";

app_info = vcf::get_app_info(app:app, port:port, kb_ver: 'Host/Cisco_TelePresence_Conductor/Version');

constraints = [
  { "min_version" : "1.0.0", "fixed_version" : "4.3.4" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

