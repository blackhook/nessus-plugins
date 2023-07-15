#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152986);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-5661",
    "CVE-2019-11041",
    "CVE-2019-11042",
    "CVE-2019-11043",
    "CVE-2019-11044",
    "CVE-2019-11045",
    "CVE-2019-11046",
    "CVE-2019-11047",
    "CVE-2019-11048",
    "CVE-2019-11049",
    "CVE-2019-11050",
    "CVE-2019-16168",
    "CVE-2019-19645",
    "CVE-2019-19646",
    "CVE-2019-19919",
    "CVE-2020-7059",
    "CVE-2020-7060",
    "CVE-2020-7061",
    "CVE-2020-7062",
    "CVE-2020-7063",
    "CVE-2020-7064",
    "CVE-2020-7065",
    "CVE-2020-7066",
    "CVE-2020-7067",
    "CVE-2020-7068",
    "CVE-2020-7069",
    "CVE-2020-7070",
    "CVE-2020-7071",
    "CVE-2020-11655",
    "CVE-2020-11656",
    "CVE-2020-13434",
    "CVE-2020-13435",
    "CVE-2020-13630",
    "CVE-2020-13631",
    "CVE-2020-13632",
    "CVE-2020-15358",
    "CVE-2021-3449",
    "CVE-2021-3450",
    "CVE-2021-21702",
    "CVE-2021-21704",
    "CVE-2021-21705",
    "CVE-2021-23358"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Tenable SecurityCenter < 5.19.0 Multiple Vulnerabilities (TNS-2021-14)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is less 
than 5.19.0 and is therefore affected by multiple vulnerabilities in the following components: 
  - Apache FOP
  - Underscore
  - Handlebars
  - PHP
  - sqlite

Note that successful exploitation of the most serious issues can result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-14");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory or upgrade to 5.19.0 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5661");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-11656");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var patches = make_list('SC-202108.1');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
  { 'fixed_version' : '5.17.0', 'fixed_display' : '5.19.0'},
  { 'min_version' : '5.17.0', 'fixed_version' : '5.19.0', 'fixed_display' : 'Apply Patch SC-202108.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
