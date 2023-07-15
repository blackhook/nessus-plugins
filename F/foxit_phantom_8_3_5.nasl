#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104742);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id(
    "CVE-2017-10956",
    "CVE-2017-10958",
    "CVE-2017-10959",
    "CVE-2017-14819",
    "CVE-2017-14823",
    "CVE-2017-14824",
    "CVE-2017-14825",
    "CVE-2017-14826",
    "CVE-2017-14827",
    "CVE-2017-14828",
    "CVE-2017-14829",
    "CVE-2017-14830",
    "CVE-2017-14831",
    "CVE-2017-14832",
    "CVE-2017-14833",
    "CVE-2017-14834",
    "CVE-2017-14835",
    "CVE-2017-14836",
    "CVE-2017-14837",
    "CVE-2017-16571",
    "CVE-2017-16573",
    "CVE-2017-16576",
    "CVE-2017-16577",
    "CVE-2017-16579",
    "CVE-2017-16581",
    "CVE-2017-16583",
    "CVE-2017-16585",
    "CVE-2017-16586"
  );

  script_name(english:"Foxit PhantomPDF < 8.3.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
8.3.5. It is, therefore, affected by multiple arbitrary code execution
and information disclosure vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 8.3.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16586");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include('vcf.inc');

app = 'FoxitPhantomPDF';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [{
  'min_version' : '8.0',
  'max_version' : '8.3.2.25013',
  'fixed_version' : '8.3.5'
  }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
