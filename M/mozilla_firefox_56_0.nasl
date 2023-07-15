#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103680);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-7793",
    "CVE-2017-7805",
    "CVE-2017-7810",
    "CVE-2017-7811",
    "CVE-2017-7812",
    "CVE-2017-7813",
    "CVE-2017-7814",
    "CVE-2017-7815",
    "CVE-2017-7816",
    "CVE-2017-7817",
    "CVE-2017-7818",
    "CVE-2017-7819",
    "CVE-2017-7820",
    "CVE-2017-7821",
    "CVE-2017-7822",
    "CVE-2017-7823",
    "CVE-2017-7824"
  );
  script_bugtraq_id(
    101053,
    101054,
    101055,
    101057
  );
  script_xref(name:"MFSA", value:"2017-21");

  script_name(english:"Mozilla Firefox < 56 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Windows host is
prior to 56. It is, therefore, affected by multiple vulnerabilities,
some of which allow code execution and potentially exploitable crashes.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-21/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 56 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7811");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', fix:'56', severity:SECURITY_HOLE);
