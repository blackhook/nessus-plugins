##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(139377);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/02");

  script_cve_id("CVE-2020-15588");
  script_xref(name:"IAVA", value:"2020-A-0350-S");

  script_name(english:"ManageEngine Desktop Central < 10 Build 10.0.533 Integer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java-based web application that is affected by an integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Desktop Central application running on the remote host is prior to version 10 build 10.0.533. It is,
therefore, affected by an integer overflow condition due to improper handling of header values. An unauthenticated, 
remote attacker can exploit this, by sending specially crafted HTTP requests, to cause a denial of service condition 
or the execution of arbitrary code.");
  # https://www.manageengine.com/products/desktop-central/integer-overflow-vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?470f5384");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central version 10 build 10.0.533 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15588");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Desktop Central");
  script_require_ports("Services/www", 8020, 8383, 8040);

  exit(0);
}

include('vcf.inc');
include('vcf_extras_zoho.inc');

var app_info = vcf::zoho::desktop_central::get_app_info();

var constraints = [
  {'fixed_version' : '100533', 'fixed_display': '10 Build 10.0.533'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);

