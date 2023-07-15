#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102858);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/27");

  script_cve_id(
    "CVE-2017-10951",
    "CVE-2017-10952"
  );
  script_bugtraq_id(
    100409,
    100412
  );
  script_xref(name:"ZDI", value:"ZDI-17-691");
  script_xref(name:"ZDI", value:"ZDI-17-692");

  script_name(english:"Foxit PhantomPDF < 8.3.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
8.3.2. It is, therefore, affected by multiple vulnerabilities:

  - A flaw exists in the app.launchURL() method allowing
    a context-dependent attacker to potentially execute
    arbitrary code. (CVE-2017-10951)

  - A flaw in the saveAs() JavaScript function that allows
    a context-dependent attacker to write to arbitrary
    files and potentially execute arbitrary code.
    (CVE-2017-10952)

  - A flaw that is triggered during the handling of the
    createDataObject() function calls that may allow an
    attacker to create arbitrary executable files on the
    local system. 

  - A flaw exists that is triggered during the handling of
    xfa.host.gotoURL() function calls that may allow an
    attacker to execute arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-17-691/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-17-692/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 8.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10951");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/31");

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
  'max_version' : '8.3.1.21155',
  'fixed_version' : '8.3.2'
  }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
