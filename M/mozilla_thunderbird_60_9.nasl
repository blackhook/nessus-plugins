#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-29.
# The text itself is copyright (C) Mozilla Foundation.


include("compat.inc");

if (description)
{
  script_id(128775);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id(
    "CVE-2019-11739",
    "CVE-2019-11740",
    "CVE-2019-11742",
    "CVE-2019-11743",
    "CVE-2019-11744",
    "CVE-2019-11746",
    "CVE-2019-11752"
  );
  script_xref(name:"MFSA", value:"2019-29");

  script_name(english:"Mozilla Thunderbird < 60.9 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 60.9. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2019-29 advisory. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-29/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 60.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(
  installs:installs, 
  product:'thunderbird', 
  esr:FALSE, 
  fix:'60.9', 
  xss:TRUE, 
  severity:SECURITY_HOLE
);
