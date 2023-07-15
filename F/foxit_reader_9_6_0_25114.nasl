#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128422);
  script_version("1.1");
  script_cvs_date("Date: 2019/09/03  9:20:03");

  script_name(english:"Foxit Reader 9.0 < 9.6.0.25114 Security Bypass Vulnerability");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit Reader application installed on the remote Windows host is prior to 9.6.0.25114.
It is, therefore affected by a security bypass vulnerability. Safe reading mode may be disabled when
users update an existing installation of Foxit Reader from within the application, which could be exploited
by an attacker to allow command execution or unauthorised data transmission.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 9.6.0.25114 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");
  # https://www.foxitsoftware.com/support/security-bulletins.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f244c3e");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

app = 'Foxit Reader';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '9.0', 'fixed_version' : '9.6.0.25114' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
