#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109919);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-5846",
    "CVE-2016-2125",
    "CVE-2016-2126",
    "CVE-2016-10142",
    "CVE-2018-9849"
  );
  script_bugtraq_id(
    26378,
    94988,
    94994,
    95797,
    104160
  );

  script_name(english:"Pulse Connect Secure Multiple Vulnerabilities (SA43730)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch or upgrade to version 9.0R1.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pulse Connect
Secure running on the remote host is affected by multiple
vulnerabilities. Refer to the vendor advisory for additional
information.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA43730
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c6b4e69");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate version referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2125");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_connect_secure");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

port = get_http_port(default:443, embedded:TRUE);
app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

constraints = [
 {'min_version':'8.3.1', 'fixed_version':'8.3.5.63409', 'fixed_display':'8.3R5'},
 {'min_version':'8.2.1', 'fixed_version':'8.2.11.63995', 'fixed_display':'8.2R11'},
 {'min_version':'8.1.1', 'fixed_version':'8.1.14.59737', 'fixed_display':'8.1R14'},
 # Everything else and suggest upgrade to latest
 # '8.1R0' is not a version, but is used as a ceiling
 {'min_version':'0.0', 'fixed_version':'8.1.0', 'fixed_display':'9.0R1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
