#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154004);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id(
    "CVE-2021-34948",
    "CVE-2021-34949",
    "CVE-2021-34950",
    "CVE-2021-34951",
    "CVE-2021-34952",
    "CVE-2021-34953",
    "CVE-2021-34954",
    "CVE-2021-34955",
    "CVE-2021-34956",
    "CVE-2021-34957",
    "CVE-2021-34958",
    "CVE-2021-34959",
    "CVE-2021-34960",
    "CVE-2021-34961",
    "CVE-2021-34962",
    "CVE-2021-34963",
    "CVE-2021-34964",
    "CVE-2021-34965",
    "CVE-2021-34966",
    "CVE-2021-34967",
    "CVE-2021-34968",
    "CVE-2021-34969",
    "CVE-2021-34970",
    "CVE-2021-34971",
    "CVE-2021-34972",
    "CVE-2021-34973",
    "CVE-2021-34974",
    "CVE-2021-34975",
    "CVE-2021-34976",
    "CVE-2021-40326",
    "CVE-2021-41780",
    "CVE-2021-41781",
    "CVE-2021-41782",
    "CVE-2021-41783",
    "CVE-2021-41784",
    "CVE-2021-41785"
  );
  script_xref(name:"IAVA", value:"2021-A-0535-S");

  script_name(english:"Foxit PDF Reader < 11.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Reader application (previously named Foxit Reader) installed on the remote
Windows host is prior to 11.1. It is, therefore affected by multiple vulnerabilities:

  - Foxit PDF Reader before 11.1 and PDF Editor before 11.1, and PhantomPDF before 10.1.6, allow attackers to
    trigger a use-after-free and execute arbitrary code because JavaScript is mishandled. (CVE-2021-41780,
    CVE-2021-41781, CVE-2021-41782, CVE-2021-41783, CVE-2021-41784, CVE-2021-41785)

  - Foxit PDF Reader before 11.1 and PDF Editor before 11.1, and PhantomPDF before 10.1.6, mishandle hidden
    and incremental data in signed documents. An attacker can write to an arbitrary file, and display
    controlled contents, during signature verification. (CVE-2021-40326)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Reader version 11.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41785");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Foxit Reader', win_local:TRUE);

var constraints = [
  { 'max_version' : '11.0.1.49938', 'fixed_version' : '11.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
