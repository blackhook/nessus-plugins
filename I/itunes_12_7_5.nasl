#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110384);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-4188",
    "CVE-2018-4190",
    "CVE-2018-4192",
    "CVE-2018-4199",
    "CVE-2018-4200",
    "CVE-2018-4201",
    "CVE-2018-4204",
    "CVE-2018-4214",
    "CVE-2018-4218",
    "CVE-2018-4222",
    "CVE-2018-4224",
    "CVE-2018-4225",
    "CVE-2018-4226",
    "CVE-2018-4232",
    "CVE-2018-4233",
    "CVE-2018-4246"
  );
  script_bugtraq_id(103961, 104378);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2018-06-01-7");

  script_name(english:"Apple iTunes < 12.7.5 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.7.5. It is, therefore, affected by multiple vulnerabilities
as referenced in the HT208852 advisory.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208852");
  # https://lists.apple.com/archives/security-announce/2018/Jun/msg00006.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?375c8685");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.7.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4246");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Safari Proxy Object Type Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

# Ensure this is Windows
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"iTunes Version", win_local:TRUE);

constraints = [{"fixed_version" : "12.7.5"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
