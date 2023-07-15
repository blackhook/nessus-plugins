##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(171868);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/24");

  script_cve_id("CVE-2022-37436");

  script_name(english:"Tenable SecurityCenter 5.22.0 / 5.23.1 / 6.0.0 Apache Header Truncation (TNS-2023-06)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a third-party software vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host 
has a third-party software vulnerability in Apache HTTP Server. Prior to Apache HTTP Server 2.4.55, 
a malicious backend can cause the response headers to be truncated early, resulting in some headers 
being incorporated into the response body. If the later headers have any security purpose, they will not 
be interpreted by the client.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2023-06");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2023.htm#2023022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f594ce01");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37436");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_ports("installed_sw/Tenable SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

var patches = make_list('SC-202302.2');
var app_info = vcf::tenable_sc::get_app_info();

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [
    { 'min_version' : '5.22.0', 'max_version': '6.0.0', 'fixed_display' : 'Apply Patch SC-202302.2'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
