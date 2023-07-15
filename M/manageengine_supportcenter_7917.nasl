#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##


include('deprecated_nasl_level.inc');
include('compat.inc');


if (description)
{
  script_id(72257);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/23");

  script_bugtraq_id(65199);
  script_xref(name:"EDB-ID", value:"31262");

  script_name(english:"ManageEngine SupportCenter Plus < 7.9 Build 7917 attach Parameter Directory Traversal");
  script_summary(english:"Checks version of ManageEngine SupportCenter Plus");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a web application affected by a directory
traversal vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of ManageEngine SupportCenter Plus
prior to version 7.9 build 7917.  It is, therefore, affected by a
directory traversal vulnerability related to 'WorkOrder.do' and
attachments that could allow an attacker to download sensitive files."
  );
  script_set_attribute(attribute:"see_also", value:"https://supportcenter.wiki.zoho.com/ReadMe-V2.html#7917");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ManageEngine SupportCenter version 7.9 build 7917 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-100002");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:manageengine:supportcenter_plus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("manageengine_supportcenter_detect.nasl");
  script_require_keys("installed_sw/ManageEngine SupportCenter");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_zoho.inc');
include('http.inc');

var port = get_http_port(default:8080);
var appname = 'ManageEngine SupportCenter';

var app_info = vcf::zoho::fix_parse::get_app_info(app:appname, port:port);

var constraints = [
  {'fixed_version': '7917', 'fixed_display' : '7.9 Build 7917'}
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);

