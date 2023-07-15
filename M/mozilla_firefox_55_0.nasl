#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102359);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-7753",
    "CVE-2017-7779",
    "CVE-2017-7780",
    "CVE-2017-7781",
    "CVE-2017-7782",
    "CVE-2017-7783",
    "CVE-2017-7784",
    "CVE-2017-7785",
    "CVE-2017-7786",
    "CVE-2017-7787",
    "CVE-2017-7788",
    "CVE-2017-7789",
    "CVE-2017-7790",
    "CVE-2017-7791",
    "CVE-2017-7792",
    "CVE-2017-7794",
    "CVE-2017-7796",
    "CVE-2017-7797",
    "CVE-2017-7798",
    "CVE-2017-7799",
    "CVE-2017-7800",
    "CVE-2017-7801",
    "CVE-2017-7802",
    "CVE-2017-7803",
    "CVE-2017-7804",
    "CVE-2017-7806",
    "CVE-2017-7807",
    "CVE-2017-7808",
    "CVE-2017-7809"
  );
  script_bugtraq_id(
    100196,
    100197,
    100198,
    100199,
    100201,
    100202,
    100203,
    100206,
    100234
  );
  script_xref(name:"MFSA", value:"2017-18");

  script_name(english:"Mozilla Firefox < 55 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Firefox installed on the remote Windows host is
prior to 55. It is, therefore, affected by multiple vulnerabilities,
some of which allow code execution and potentially exploitable crashes.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-18/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox version 55 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7779");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/10");

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

mozilla_check_version(installs:installs, product:'firefox', fix:'55', severity:SECURITY_HOLE);
