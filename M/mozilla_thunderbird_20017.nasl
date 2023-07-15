#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(34294);
  script_version("1.18");

  script_cve_id(
    "CVE-2008-0016",
    "CVE-2008-3835",
    "CVE-2008-4058",
    "CVE-2008-4059",
    "CVE-2008-4060",
    "CVE-2008-4061",
    "CVE-2008-4062",
    "CVE-2008-4063",
    "CVE-2008-4064",
    "CVE-2008-4065",
    "CVE-2008-4066",
    "CVE-2008-4067",
    "CVE-2008-4068",
    "CVE-2008-4070"
  );
  script_bugtraq_id(31346, 31411);
  script_xref(name:"Secunia", value:"32007");

  script_name(english:"Mozilla Thunderbird < 2.0.0.17 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is affected by various security
issues :

  - Using a specially crafted UTF-8 URL in a hyperlink, an
    attacker might be able to exploit a stack buffer
    overflow in the Mozilla URL parsing routes to execute
    arbitrary code (MFSA 2008-37).

  - It is possible to bypass the same-origin check in
    'nsXMLDocument::OnChannelRedirect()' (MFSA 2008-38).

  - Privilege escalation is possible via 'XPCnativeWrapper'
    pollution (MFSA 2008-41).

  - There are several stability bugs in the browser engine
    that coould lead to crashes with evidence of memory
    corruption (MFSA 2008-42).

  - Certain BOM characters and low surrogate characters,
    if HTML-escaped, are stripped from JavaScript code
    before it is executed, which could allow for cross-
    site scripting attacks (MFSA 2008-43).

  - The 'resource:' protocol allows directory traversal
    on Linux when using URL-encoded slashes, and it can
    be used to bypass restrictions on local HTML files
    (MFSA 2008-44).

  - There is a heap-based buffer overflow that can be
    triggered when canceling a newsgroup message
    (MFSA 2008-46).");
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-37/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-38/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-41/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-42/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-43/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-44/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-46/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Mozilla Thunderbird 2.0.0.17 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 79, 119, 189, 264, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/26");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/09/23");
 script_cvs_date("Date: 2018/07/16 14:09:15");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.17', severity:SECURITY_HOLE);
