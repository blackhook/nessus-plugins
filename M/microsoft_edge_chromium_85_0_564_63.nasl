#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141009);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2020-15960",
    "CVE-2020-15961",
    "CVE-2020-15962",
    "CVE-2020-15963",
    "CVE-2020-15964",
    "CVE-2020-15965",
    "CVE-2020-15966"
  );

  script_name(english:"Microsoft Edge (Chromium) < 85.0.564.63 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge installed on the remote Windows host is prior to 85.0.564.63. It is, therefore, affected
by multiple vulnerabilities as referenced in the ADV200002-9-23-2020 advisory.

  - Heap buffer overflow in storage in Google Chrome prior to 85.0.564.63 allowed a remote attacker to
    potentially perform out of bounds memory access via a crafted HTML page. (CVE-2020-15960)

  - Insufficient policy validation in extensions in Google Chrome prior to 85.0.564.63 allowed an attacker
    who convinced a user to install a malicious extension to potentially perform a sandbox escape via a
    crafted Chrome Extension. (CVE-2020-15961)

  - Insufficient policy validation in serial in Google Chrome prior to 85.0.564.63 allowed a remote attacker
    to potentially perform out of bounds memory access via a crafted HTML page. (CVE-2020-15962)

  - Insufficient policy enforcement in extensions in Google Chrome prior to 85.0.564.63 allowed an attacker
    who convinced a user to install a malicious extension to potentially perform a sandbox escape via a
    crafted Chrome Extension. (CVE-2020-15963)

  - Insufficient data validation in media in Google Chrome prior to 85.0.564.63 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-15964)

  - Type confusion in V8 in Google Chrome prior to 85.0.564.63 allowed a remote attacker to potentially
    perform out of bounds memory access via a crafted HTML page. (CVE-2020-15965)

  - Insufficient policy enforcement in extensions in Google Chrome prior to 85.0.564.63 allowed an attacker
    who convinced a user to install a malicious extension to obtain potentially sensitive information via a
    crafted Chrome Extension. (CVE-2020-15966)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV200002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?083510ae");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge version 85.0.564.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15965");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15963");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');
app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);
constraints = [
  { 'fixed_version' : '85.0.564.63' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
