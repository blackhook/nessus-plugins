##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163932);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-26070");
  script_xref(name:"IAVA", value:"2022-A-0219-S");

  script_name(english:"Splunk Enterprise  < 8.1.0 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk running on the remote web server is Splunk
Enterprise prior to 8.1. It is, therefore, be affected by an information disclosure vulnerability where, when
handling a mismatched authentication cookie, the application leaks the internal error message in the response which
contains the Splunk Enterprise local system path.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.splunk.com/en_us/product-security/announcements/svd-2022-0507.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30f9c838");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to version 8.1.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26070");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("splunk_web_detect.nasl", "splunkd_detect.nasl", "macos_splunk_installed.nbin", "splunk_win_installed.nbin");
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include('vcf_extras_splunk.inc');

var app_info = vcf::splunk::get_app_info();

var constraints = [
  { 'fixed_version' : '8.1.0', 'license' : 'Enterprise' },
];

vcf::splunk::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

