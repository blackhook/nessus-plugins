#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154240);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-33193", "CVE-2021-34798", "CVE-2021-40438");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");

  script_name(english:"Tenable SecurityCenter 5.16.0 < 5.19.2 Multiple Vulnerabilities (TNS-2021-17)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is prior to
5.19.2 and is missing a security patch, SC-202110.1.  It is therefore, affected by multiple vulnerabilities in the 
Apache subcomponent of Security Center. 

Note that successful exploitation of the most serious issues can result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2021-17");
  # https://docs.tenable.com/releasenotes/Content/tenablesc/tenablesc2021101.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29d90154");
  script_set_attribute(attribute:"solution", value:
"Apply the security patch referenced in the vendor advisory or upgrade to 5.19.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40438");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/19");

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

var patches = make_list('SC-202110.1');
var app_info = vcf::tenable_sc::get_app_info();
var min_version = '5.16.0';

vcf::tenable_sc::check_for_patch(app_info:app_info, patches:patches);

var constraints = [{ 'min_version' : min_version, 'fixed_version' : '5.19.2', 'fixed_display' : 'Apply Patch SC-202110.1' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
