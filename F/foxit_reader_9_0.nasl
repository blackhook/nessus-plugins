#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104433);
  script_version("1.7");
  script_cvs_date("Date: 2019/03/27 13:17:51");

  script_cve_id(
    "CVE-2017-14694",
    "CVE-2017-10959",
    "CVE-2017-16588",
    "CVE-2017-16589"
  );
  script_bugtraq_id(101009);
  script_xref(name:"ZDI", value:"ZDI-17-856");
  script_xref(name:"ZDI", value:"ZDI-17-857");

  script_name(english:"Foxit Reader < 9.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 9.0. It is, therefore, affected by multiple arbitrary code
execution and information disclosure vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10959");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

app = 'Foxit Reader';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [{
  'min_version' : '8.0',
  'max_version' : '8.3.2.25013',
  'fixed_version' : '9.0'
  }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
