#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(129494);
  script_version("1.7");
  script_cvs_date("Date: 2020/02/06");

  script_cve_id(
    "CVE-2019-5031",
    "CVE-2019-13123",
    "CVE-2019-13124",
    "CVE-2019-17183"
  );

  script_name(english:"Foxit Reader < 9.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Foxit Reader");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit Reader application installed on the remote Windows host is prior to 9.7. It is,
therefore affected by multiple vulnerabilities:

  - Addressed potential issues where the application could be exposed to Remote Code Execution vulnerability
    and crash due to the unexpected error or out-of-memory in V8 Engine when executing certain JavaScript.
    (CVE-2019-5031, CVE-2019-13123, CVE-2019-13124)

  - Addressed a potential issue where the application could be exposed to Access Violation vulnerability and
    crash when it was launched on the condition that there was no enough memory in the current system.
    (CVE-2019-17183)

  - Addressed potential issues where the application could be exposed to Use-After-Free Remote Code Execution
    vulnerability when deleting Field with the nested scripts.

  - Addressed potential issues where the application could be exposed to Type Confusion Remote Code Execution
    vulnerability and crash when parsing TIFF files as the application failed to set decoding information for
    images properly.

Additionally, the application was affected by multiple potential denial of service, and remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  # https://blog.talosintelligence.com/2019/09/vuln-spotlight-foxit-PDF-JavaScript-sept-2019.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0dc209a4");
  # https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0793
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bd507aa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 9.7 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5031");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

app = 'Foxit Reader';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '9.0', 'max_version' : '9.6.0.25114', 'fixed_version' : '9.7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
