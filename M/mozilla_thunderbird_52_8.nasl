#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109946);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-5150",
    "CVE-2018-5154",
    "CVE-2018-5155",
    "CVE-2018-5159",
    "CVE-2018-5161",
    "CVE-2018-5162",
    "CVE-2018-5168",
    "CVE-2018-5170",
    "CVE-2018-5174",
    "CVE-2018-5178",
    "CVE-2018-5183",
    "CVE-2018-5184",
    "CVE-2018-5185"
  );
  script_bugtraq_id(104136, 104138);

  script_name(english:"Mozilla Thunderbird < 52.8 Multiple Vulnerabilities (EFAIL)");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Thunderbird installed on the remote Windows
host is prior to 52.8 It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-13/");
  script_set_attribute(attribute:"see_also", value:"https://efail.de/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 52.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5183");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', fix:'52.8', severity:SECURITY_HOLE);
