##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(117639);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/02");

  script_cve_id("CVE-2018-13411", "CVE-2018-13412");
  script_bugtraq_id(105348);
  script_xref(name:"IAVA", value:"2018-A-0302-S");

  script_name(english:"ManageEngine Desktop Central 10 < Build 100282 Remote Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java-based web application that is
affected by a remote privilege escalation.");
  script_set_attribute(attribute:"description", value:
"The ManageEngine Desktop Central application running on the remote
host is version 10 prior to build 100282. It is, therefore, affected by
a remote privilege escalation vulnerability.");
  # https://www.manageengine.com/products/desktop-central/elevation-of-system-privilege.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddf441fc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine Desktop Central version 10 build 100282 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-13411");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zohocorp:manageengine_desktop_central");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_desktop_central_detect.nbin");
  script_require_keys("installed_sw/ManageEngine Desktop Central");
  script_require_ports("Services/www", 8020, 8383, 8040);

  exit(0);
}

include('vcf.inc');
include('vcf_extras_zoho.inc');

var app_info = vcf::zoho::desktop_central::get_app_info();

var constraints = [
  {'fixed_version' : '100282', 'fixed_display': '10 Build 100282'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
