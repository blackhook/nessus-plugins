#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119258);
  script_version("1.1");
  script_cvs_date("Date: 2018/11/28 12:12:24");

  script_name(english:"Foxit PhantomPDF < 7.3.11 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
7.3.11. It is, therefore, affected by multiple vulnerabilities."
);
  # https://www.foxitsoftware.com/support/security-bulletins.php#content-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24cd2afa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 7.3.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}
include("vcf.inc");

app = "FoxitPhantomPDF";

app_info = vcf::get_app_info(app:app, win_local:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
      { "fixed_version" : "7.3.11", "max_version": "7.3.9.816" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
