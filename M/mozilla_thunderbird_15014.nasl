#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(29743);
  script_version("1.15");

  script_cve_id("CVE-2007-5339", "CVE-2007-5340");
  script_bugtraq_id(26132);

  script_name(english:"Mozilla Thunderbird < 1.5.0.14 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Mozilla Thunderbird");

  script_set_attribute(  attribute:"synopsis",  value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(  attribute:"description",   value:
"The remote version of Mozilla Thunderbird suffers from various
security issues, several of which may lead to execution of arbitrary
code on the affected host subject to the user's privileges."  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-29/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2007-40/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 1.5.0.14 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/10/19");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/10/18");
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

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'1.5.0.14', severity:SECURITY_HOLE);