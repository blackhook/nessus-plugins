#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59409);
  script_version("1.16");
  script_cvs_date("Date: 2018/07/16 14:09:15");

  script_cve_id(
    "CVE-2012-0441",
    "CVE-2012-1937",
    "CVE-2012-1938",
    "CVE-2012-1940",
    "CVE-2012-1941",
    "CVE-2012-1942",
    "CVE-2012-1943",
    "CVE-2012-1944",
    "CVE-2012-1946",
    "CVE-2012-1947",
    "CVE-2012-1964"
 );
  script_bugtraq_id(
    53791,
    53792,
    53793,
    53794,
    53796,
    53798,
    53800,
    53801,
    53803,
    53807,
    54581
  );

  script_name(english:"Mozilla Thunderbird < 13.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains a mail client that is potentially
affected by several vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The installed version of Thunderbird is earlier than 13.0 and thus, 
is potentially affected by the following security issues :

  - An error exists in the ASN.1 decoder when handling zero
    length items that can lead to application crashes.
    (CVE-2012-0441)

  - Multiple memory corruption errors exist. (CVE-2012-1937,
    CVE-2012-1938)

  - Two heap-based buffer overflows and one heap-based use-
    after-free error exist and are potentially exploitable.
    (CVE-2012-1940, CVE-2012-1941, CVE-2012-1947)

  - Two arbitrary DLL load issues exist related to the
    application update and update service functionality.
    (CVE-2012-1942, CVE-2012-1943)

  - The inline-script blocking feature of the 'Content
    Security Policy' (CSP) does not properly block inline
    event handlers. This error allows remote attackers to
    more easily carry out cross-site scripting attacks.
    (CVE-2012-1944)

  - A use-after-free error exists related to replacing or
    inserting a node into a web document. (CVE-2012-1946)

  - An error exists related to the certificate warning page
    that can allow 'clickjacking' thereby tricking a user
    into accepting unintended certificates. (CVE-2012-1964)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-34/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-35/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-36/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-38/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-39/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-40/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2012-54/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 13.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'13.0', severity:SECURITY_HOLE, xss:TRUE);
