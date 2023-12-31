#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47784);
  script_version("1.20");
  script_cvs_date("Date: 2018/07/16 14:09:15");

  script_cve_id("CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1207", "CVE-2010-1210",
                "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213", "CVE-2010-1215",
                "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754");
  script_bugtraq_id(41852, 41853, 41859, 41860, 41866, 41871, 41872, 41878);
  script_xref(name:"Secunia", value:"40642");

  script_name(english:"Mozilla Thunderbird 3.1.x < 3.1.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 3.1.1.  Such
versions are potentially affected by the following security issues :

  - Multiple memory safety bugs could result in memory
    corruption, potentially resulting in arbitrary code
    execution. (MFSA 2010-34)

  - It may be possible to run arbitrary JavaScript with
    chrome privileges using SJOW and fast native
    function. (MFSA 2010-38) 

 - The array class used to store CSS values is affected
    by an integer overflow vulnerability. (MFSA 2010-39)

  - An integer overflow vulnerability exists in the
    'selection' attribute of XUL <tree> element.
    (MFSA 2010-40)

  - A buffer overflow vulnerability in Mozilla graphics
    code could lead to arbitrary code execution.
    (MFSA 2010-41)

  - It is possible to read and parse resources from other
    domains even when the content is not valid JavaScript
    leading to cross-domain data disclosure. (MFSA 2010-42)

  - The canvas element can be used to read data from another
    site leading to a same-origin bypass vulnerability.
    (MFSA 2010-43)

  - Characters mapped to U+FFFD in 8 bit encodings could
    cause subsequent characters to disappear, potentially
    contributing to cross-site scripting issues on certain
    websites. (MFSA 2010-44)

  - It is possible to read data across domains by
    injecting bogus CSS selectors into a target site.
    (MFSA 2010-46)

  - Potentially sensitive URL parameters could be leaked
    across domains via script errors. (MFSA 2010-47)");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-34/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-38/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-39/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-40/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-41/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-42/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-43/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-44/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-46/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-47/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/23"); # (MFSA 2010-46)
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/21");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.1.1', min:'3.1.0', severity:SECURITY_HOLE);
