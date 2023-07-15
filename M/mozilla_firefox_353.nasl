#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40931);
  script_version("1.17");
  script_cve_id(
    "CVE-2009-3069",
    "CVE-2009-3072",
    "CVE-2009-3073",
    "CVE-2009-3077",
    "CVE-2009-3078",
    "CVE-2009-3079"
  );
  script_bugtraq_id(36343);
  script_xref(name:"Secunia", value:"36671");

  script_name(english:"Firefox 3.5.x < 3.5.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."  );
  script_set_attribute( attribute:"description",  value:
"The installed version of Firefox 3.5 is earlier than 3.5.3.  Such
versions are potentially affected by the following security issues :

  - Multiple memory corruption vulnerabilities could potentially
    allow arbitrary code execution. (MFSA 2009-47)

  - The columns of a XUL tree element can manipulated in
    a way that leads to a dangling pointer.  A remote attacker
    could exploit this to crash the browser, or execute
    arbitrary code. (MFSA 2009-49)

  - A URL containing certain Unicode characters with tall
    tall-line height is displayed incorrectly in the location bar.
    A remote attacker could use this to prevent a user from
    seeing the full URL of a malicious website. (MFSA 2009-50)

  - A remote attacker can leverage 'BrowserFeedWriter' to
    execute JavaScript code with Chrome privileges.
    (MFSA 2009-51)"  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-47/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-49/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-50/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-51/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Firefox 3.5.3 or later"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/09"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/09"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/10"
  );
 script_cvs_date("Date: 2018/07/16 14:09:14");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.5.3', min:'3.5', severity:SECURITY_HOLE);
