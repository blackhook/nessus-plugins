#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103506);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-7081",
    "CVE-2017-7087",
    "CVE-2017-7090",
    "CVE-2017-7091",
    "CVE-2017-7092",
    "CVE-2017-7093",
    "CVE-2017-7094",
    "CVE-2017-7095",
    "CVE-2017-7096",
    "CVE-2017-7098",
    "CVE-2017-7099",
    "CVE-2017-7100",
    "CVE-2017-7102",
    "CVE-2017-7104",
    "CVE-2017-7107",
    "CVE-2017-7109",
    "CVE-2017-7111",
    "CVE-2017-7117",
    "CVE-2017-7120"
  );
  script_bugtraq_id(
    100985,
    100986,
    100994,
    100995,
    100998,
    101005,
    101006
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-09-25-7");

  script_name(english:"Apple iTunes < 12.7 WebKit Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.7. It is, therefore, affected by multiple vulnerabilities 
in webkit.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208141");
  # https://lists.apple.com/archives/security-announce/2017/Sep/msg00011.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83c17945");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7120");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

# Ensure this is Windows
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"iTunes Version", win_local:TRUE);

constraints = [{"fixed_version" : "12.7"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:true});
