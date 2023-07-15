#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(175129);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2023-24539", "CVE-2023-24540", "CVE-2023-29400");
  script_xref(name:"IAVB", value:"2023-B-0029-S");

  script_name(english:"Golang < 1.19.9 / 1.20.x < 1.20.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Golang Go installed on the remote host is affected by multiple vulnerabilities the html/template
component:

 - Angle brackets (<>) are not considered dangerous characters when inserted into CSS contexts. Templates
   containing multiple actions separated by a '/' character could result in unexpectedly closing the CSS
   context and allowing for injection of unexpected HMTL, if executed with untrusted input. (CVE-2023-24539)

 - Not all valid JavaScript whitespace characters are considered to be whitespace. Templates containing
   other whitespace characters in JavaScript contexts that also contain actions may not be properly
   sanitized during execution. (CVE-2023-24540)

 - Templates containing actions in unquoted HTML attributes executed with empty input could result in output
   that would have unexpected results when parsed due to HTML normalization rules. This may allow injection
   of arbitrary attributes into tags. (CVE-2023-29400)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/golang/go/issues/59720");
  script_set_attribute(attribute:"see_also", value:"https://github.com/golang/go/issues/59721");
  script_set_attribute(attribute:"see_also", value:"https://github.com/golang/go/issues/59722");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Golang Go version 1.19.9, 1.20.4, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24540");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("golang_win_installed.nbin");
  script_require_keys("installed_sw/Golang Go Programming Language", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Golang Go Programming Language', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '1.19.9' },
  { 'min_version' : '1.20', 'fixed_version' : '1.20.4' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
