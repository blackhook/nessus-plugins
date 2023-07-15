#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155300);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/19");

  script_cve_id("CVE-2021-40127");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz62174");
  script_xref(name:"CISCO-SA", value:"cisco-sa-smb-switches-web-dos-xMyFFkt8");
  script_xref(name:"IAVA", value:"2021-A-0548-S");

  script_name(english:"Cisco Small Business 200, 300, and 500 Series Switches Web-Based Management Interface DoS (cisco-sa-smb-switches-web-dos-xMyFFkt8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business 200, 300, and 500 Series Switches are affected by a
vulnerability in the web-based management interface due to improper validation of HTTP requests. An unauthenticated,
remote attacker can exploit this to cause a denial of service (DoS) condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-smb-switches-web-dos-xMyFFkt8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bce2073");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz62174");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz62174");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40127");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_series_switch");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_switch_detect.nbin");
  script_require_keys("installed_sw/Cisco Small Business Series Switch");

  exit(0);
}

include('install_func.inc');
include('http.inc');

var app_name = 'Cisco Small Business Series Switch';
var port = get_http_port(default:443);

# Version is always unknown so use get_single_install() instead of vcf::get_app_info()
var install = get_single_install(app_name:app_name, exit_if_unknown_ver:FALSE, port:port);

var model = install['model'];

if (model !~ "S[GF][235]00")
  audit(AUDIT_HOST_NOT, 'an affected model');

var report =
  '\n    Model         : ' + model +
  '\n    Fixed Version : See vendor advisory' +
  '\n';
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
