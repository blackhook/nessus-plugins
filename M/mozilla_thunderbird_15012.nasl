#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(25350);
  script_version("1.20");

  script_cve_id("CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868");
  script_bugtraq_id(23257, 24242);

  script_name(english:"Mozilla Thunderbird < 1.5.0.12 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Mozilla Thunderbird");
 
  script_set_attribute(  attribute:"synopsis",  value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(  attribute:"description",   value:
"The remote version of Mozilla Thunderbird suffers from various
security issues, at least one that may lead to execution of arbitrary
code on the affected host subject to the user's privileges."  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-12/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-15/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 1.5.0.12 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/02");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/05/30");
 script_cvs_date("Date: 2018/07/16 14:09:15");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'1.5.0.12', severity:SECURITY_HOLE);