#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109398);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2017-14458",
    "CVE-2017-17557",
    "CVE-2018-3842",
    "CVE-2018-3850",
    "CVE-2018-3853"
  );
  script_bugtraq_id(103942);
  script_xref(name:"ZDI", value:"ZDI-18-312");
  script_xref(name:"ZDI", value:"ZDI-18-313");
  script_xref(name:"ZDI", value:"ZDI-18-315");
  script_xref(name:"ZDI", value:"ZDI-18-329");
  script_xref(name:"ZDI", value:"ZDI-18-330");
  script_xref(name:"ZDI", value:"ZDI-18-331");
  script_xref(name:"ZDI", value:"ZDI-18-332");
  script_xref(name:"ZDI", value:"ZDI-18-335");
  script_xref(name:"ZDI", value:"ZDI-18-339");
  script_xref(name:"ZDI", value:"ZDI-18-340");
  script_xref(name:"ZDI", value:"ZDI-18-341");
  script_xref(name:"ZDI", value:"ZDI-18-342");
  script_xref(name:"ZDI", value:"ZDI-18-344");
  script_xref(name:"ZDI", value:"ZDI-18-345");
  script_xref(name:"ZDI", value:"ZDI-18-346");
  script_xref(name:"ZDI", value:"ZDI-18-348");
  script_xref(name:"ZDI", value:"ZDI-18-349");
  script_xref(name:"ZDI", value:"ZDI-18-350");
  script_xref(name:"ZDI", value:"ZDI-18-351");
  script_xref(name:"ZDI", value:"ZDI-18-352");
  script_xref(name:"ZDI", value:"ZDI-18-354");
  script_xref(name:"ZDI", value:"ZDI-18-358");
  script_xref(name:"ZDI", value:"ZDI-18-359");

  script_name(english:"Foxit PhantomPDF < 9.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
9.1. It is, therefore, affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include('vcf.inc');

app = 'FoxitPhantomPDF';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [{
  'min_version' : '9.0',
  'fixed_version' : '9.1.0.5096'
  }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
