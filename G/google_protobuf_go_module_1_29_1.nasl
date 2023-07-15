#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174168);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2023-24535");
  script_xref(name:"IAVB", value:"2023-B-0017-S");

  script_name(english:"Google Protobuf Go Module 1.29 < 1.29.1 DoS");

  script_set_attribute(attribute:"synopsis", value:
"Google Protobuf module for Go is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Google Protobuf module for Go is affected by a denial of service (DoS) vulnerability. Parsing invalid
messages with a minus sign or whitespace can lead to a denial of service.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-hw7c-3rfg-p46j");
  script_set_attribute(attribute:"see_also", value:"https://github.com/golang/protobuf/issues/1530");
  script_set_attribute(attribute:"see_also", value:"https://pkg.go.dev/vuln/GO-2023-1631");
  script_set_attribute(attribute:"solution", value:
"Update to version 1.29.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24535");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:protobuf");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("google_protobuf_go_module_linux_installed.nbin");
  script_require_keys("installed_sw/Google Protobuf");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Google Protobuf');

var constraints = [
  { 'min_version' : '1.29.0', 'fixed_version' : '1.29.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
