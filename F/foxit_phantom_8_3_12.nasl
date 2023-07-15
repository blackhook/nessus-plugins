#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(130625);
  script_version("1.3");
  script_cvs_date("Date: 2020/02/06");

  script_cve_id(
    "CVE-2019-5031",
    "CVE-2019-13123",
    "CVE-2019-13124",
    "CVE-2019-17183"
  );

  script_name(english:"Foxit PhantomPDF 8.x < 8.3.12 / 9.x < 9.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally known as Phantom) installed on the remote Windows
host is prior to 8.x < 8.3.12 / 9.x < 9.7. It is, therefore affected by multiple vulnerabilities: 

  - An out-of-bounds error exists in the V8 JavaScript engine. An unauthenticated, remote attacker can exploit
    this, by tricking a user into opening a malicious file to execute arbitrary commands. (CVE-2019-5031)

  - A denial of service (DOS) vulnerability exists in the V8 JavaScript engine due to two unique RecursiveCall 
    bugs. An unauthenticated, remote attacker can exploit this, to exhaust the available stack memory. 
    (CVE-2019-13123, CVE-2019-13124)

  - A denial of service (DOS) vulnerability exists due to a potential issue where the application could be
    exposed to an access violation vulnerability. An unauthenticated, remote attacker could exploit this, by
    launching the application under conditions where there is not enough memory in the system, to cause the 
    application to stop responding.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f244c3e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 8.3.12 / 9.7 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5031");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include('vcf.inc');

app = 'FoxitPhantomPDF';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '8.0', 'max_version' : '8.3.11.45106', 'fixed_version' : '8.3.12' },
  { 'min_version' : '9.0', 'max_version' : '9.6.0.25114', 'fixed_version' : '9.7.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
