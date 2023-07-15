#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111043);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-5188",
    "CVE-2018-12359",
    "CVE-2018-12360",
    "CVE-2018-12362",
    "CVE-2018-12363",
    "CVE-2018-12364",
    "CVE-2018-12365",
    "CVE-2018-12366",
    "CVE-2018-12368",
    "CVE-2018-12372",
    "CVE-2018-12373",
    "CVE-2018-12374"
  );
  script_bugtraq_id(104555, 104560, 104613);

  script_name(english:"Mozilla Thunderbird < 52.9 Multiple Vulnerabilities (macOS)");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS or Mac OS X host contains a mail client that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Thunderbird installed on the remote OSX 
host is prior to 52.9. It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-18/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 52.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12368");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_thunderbird_installed.nasl");
  script_require_keys("MacOSX/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Thunderbird";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

mozilla_check_version(version:version, path:path, product:'thunderbird', fix:'52.9', severity:SECURITY_HOLE);
