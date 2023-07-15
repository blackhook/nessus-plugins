#
# (C) Tenable Network Security, Inc.
#

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134302);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/10");

  script_cve_id("CVE-2019-9489");

  script_name(english:"Trend Micro Worry-Free Business Security (WFBS) Directory Traversal Vulnerability (1122250)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Trend Micro WFBS which is affected by a directory traversal vulnerability.
An unauthenticated, remote attacker can exploit this, by sending a URI that contains directory traversal 
characters, to disclose the contents of files located outside of the server's restricted path.");
  # https://success.trendmicro.com/solution/1122250
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2512a810");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Trend Micro 
  advisory 1122250.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9489");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_server_win_installed.nbin");
  script_require_keys("installed_sw/Trend Micro Worry-Free Business Security Advanced");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Trend Micro Worry-Free Business Security Advanced');
vcf::check_granularity(app_info:app_info, sig_segments:4);

constraints = [
  {'min_version':'9.0.0', 'fixed_version':'9.0.0.4394'},
  {'min_version':'9.5.0', 'fixed_version':'9.5.0.1487'},
  {'min_version':'10.0.0', 'fixed_version':'10.0.0.1531'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
