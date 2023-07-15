#
# (C) Tenable Network Security, Inc.
#




# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2019-35.
# The text itself is copyright (C) Mozilla Foundation.




include('compat.inc');

if (description)
{
  script_id(130365);
  script_version("1.4");
  script_cvs_date("Date: 2020/01/16");

  script_cve_id(
    "CVE-2019-11757",
    "CVE-2019-11758",
    "CVE-2019-11759",
    "CVE-2019-11760",
    "CVE-2019-11761",
    "CVE-2019-11762",
    "CVE-2019-11763",
    "CVE-2019-11764",
    "CVE-2019-15903"
  );
  script_xref(name:"MFSA", value:"2019-35");

  script_name(english:"Mozilla Thunderbird < 68.2");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 68.2. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2019-35 advisory.

  - In libexpat before 2.2.8, crafted XML input could fool
    the parser into changing from DTD parsing to document
    parsing too early; a consecutive call to
    XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber)
    then resulted in a heap-based buffer over-read.
    (CVE-2019-15903)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-35/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 68.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11764");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'68.2', severity:SECURITY_WARNING);

