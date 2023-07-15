#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133674);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/17");

  script_cve_id("CVE-2020-3759", "CVE-2020-3760");

  script_name(english:"Adobe Digital Editions < 4.5.11 Multiple Vulnerabilities (APSB20-07)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote Windows host is prior to 4.5.11. It is, therefore,
affected by multiple vulnerabilities: 

  - An information disclosure vulnerability exists in Adobe Digital Editions due to a buffer error. An
    unauthenticated, remote attacker can exploit this, via the internet, to disclose potentially sensitive
    information. (CVE-2020-3759)

  - A command injection vulnerability exists in Adobe Digital Editions due to improper input validation. An
    unauthenticated, remote attacker can exploit this, via the internet, to execute arbitrary commands.
    (CVE-2020-3760)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb20-07.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?589962d0");
  # https://www.adobe.com/solutions/ebook/digital-editions/release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83b06211");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_digital_editions_installed.nbin");
  script_require_keys("installed_sw/Adobe Digital Editions", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Adobe Digital Editions', win_local:TRUE);

constraints = [
  { 'fixed_version' : '4.5.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
