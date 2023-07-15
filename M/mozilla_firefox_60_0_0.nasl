#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109869);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/04");

  script_cve_id(
    "CVE-2018-5150",
    "CVE-2018-5151",
    "CVE-2018-5152",
    "CVE-2018-5153",
    "CVE-2018-5154",
    "CVE-2018-5155",
    "CVE-2018-5157",
    "CVE-2018-5158",
    "CVE-2018-5159",
    "CVE-2018-5160",
    "CVE-2018-5163",
    "CVE-2018-5164",
    "CVE-2018-5165",
    "CVE-2018-5166",
    "CVE-2018-5167",
    "CVE-2018-5168",
    "CVE-2018-5169",
    "CVE-2018-5172",
    "CVE-2018-5173",
    "CVE-2018-5174",
    "CVE-2018-5175",
    "CVE-2018-5176",
    "CVE-2018-5177",
    "CVE-2018-5180",
    "CVE-2018-5181",
    "CVE-2018-5182"
  );
  script_bugtraq_id(104136, 104139);
  script_xref(name:"MFSA", value:"2018-11");

  script_name(english:"Mozilla Firefox < 60 Multiple Critical Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
    multiple critical and high severity vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Windows
    host is prior to 60. It is, therefore, affected by multiple critical
    and high severity vulnerabilities.");
  # https://www.mozilla.org/en-US/security/advisories/mfsa2018-11/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e296858");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 60.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5151");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', fix:'60.0.0', severity:SECURITY_HOLE);
