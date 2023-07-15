#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106302);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2018-5089",
    "CVE-2018-5091",
    "CVE-2018-5095",
    "CVE-2018-5096",
    "CVE-2018-5097",
    "CVE-2018-5098",
    "CVE-2018-5099",
    "CVE-2018-5102",
    "CVE-2018-5103",
    "CVE-2018-5104",
    "CVE-2018-5117"
  );
  script_bugtraq_id(102771, 102783);
  script_xref(name:"MFSA", value:"2018-03");

  script_name(english:"Mozilla Firefox ESR < 52.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox ESR installed on the remote Windows
host is prior to 52.6. It is, therefore, affected by multiple
vulnerabilities, some of which allow code execution and potentially
exploitable crashes.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-03/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 52.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5104");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
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

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'52.6', min:'52', severity:SECURITY_HOLE);
