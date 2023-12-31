#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47126);
  script_version("1.15");
  script_cvs_date("Date: 2018/07/27 18:38:15");

  script_cve_id(
    "CVE-2008-5913",
    "CVE-2010-0183",
    "CVE-2010-1121",
    "CVE-2010-1125",
    "CVE-2010-1196",
    "CVE-2010-1197",
    "CVE-2010-1198",
    "CVE-2010-1199"
  );
  script_bugtraq_id(
    33276,
    38952,
    40701,
    41082,
    41087,
    41100,
    41102,
    41103
  );
  script_xref(name:"Secunia", value:"40326");

  script_name(english:"SeaMonkey < 2.0.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.0.5.  Such
versions are potentially affected by the following security issues :

  - A memory corruption vulnerability can lead to arbitrary
    code execution if garbage collection is carefully timed
    after DOM nodes are moved between documents.
    (MFSA 2010-25)

  - Multiple crashes can result in arbitrary code
    execution. (MFSA 2010-26)

  - An error in 'nsCycleCollector' may allow access to a
    previously freed resource leading to arbitrary code
    execution. (MFSA 2010-27)

  - A plugin is allowed to hold a reference to an object
    owned by a second plugin even after the second plugin
    is unloaded and the referenced object no longer exists.
    This could allow arbitrary code execution. (MFSA 2010-28)

  - An error in 'nsGenericDOMDataNode' allows a buffer
    overflow in certain DOM nodes leading to arbitrary code
    execution. (MFSA 2010-29)

  - An error in a XSLT node sorting function contains an
    integer overflow leading to application crashes and
    possible arbitrary code execution. (MFSA 2010-30)

  - A cross-site scripting vulnerability exists when
    content from one domain is embedded in pages from other
    domains and the 'focus()' function is used, leading to
    information disclosure. (MFSA 2010-31)

  - The HTTP header, 'Content-Disposition: attachment', is
    ignored when the HTTP header 'Content-Type: multipart'
    is present. This could allow cross-site scripting to
    occur. (MFSA 2010-32)

  - The pseudo-random number generator is only seeded once
    per browsing session and 'Math.random()' may be used to
    recover the seed value allowing the browser instance
    to be tracked across different websites. (MFSA 2010-33)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-25/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-26/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-27/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-28/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-29/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-30/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-31/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-32/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-33/");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/23");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.0.5', severity:SECURITY_HOLE);
