#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105044);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-7826", "CVE-2017-7828", "CVE-2017-7830");
  script_bugtraq_id(101832);

  script_name(english:"Mozilla Thunderbird < 52.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Mozilla Thunderbird installed on the remote Windows
host is prior to 52.5 It is, therefore, affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-26/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 52.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7826");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', fix:'52.5', severity:SECURITY_HOLE);
