#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55902);
  script_version("1.14");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_cve_id(
    "CVE-2011-0084",
    "CVE-2011-2985",
    "CVE-2011-2986",
    "CVE-2011-2987",
    "CVE-2011-2988",
    "CVE-2011-2989",
    "CVE-2011-2990",
    "CVE-2011-2991",
    "CVE-2011-2992",
    "CVE-2011-2993",
    "CVE-2011-2999"
  );
  script_bugtraq_id(
    49213,
    49224,
    49226,
    49227,
    49239,
    49242,
    49243,
    49245,
    49246,
    49248,
    49848
  );

  script_name(english:"Firefox < 6.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Firefox is earlier than 6.0 and thus, is
potentially affected by the following security issues :

  - A dangling pointer vulnerability exists in an SVG text
    manipulation routine. (CVE-2011-0084)

  - Several memory safety bugs exist in the browser engine
    that may permit remote code execution. (CVE-2011-2985,
    CVE-2011-2989, CVE-2011-2991, CVE-2011-2992)

  - A cross-origin data theft vulnerability exists when
    using canvas and Windows D2D hardware acceleration.
    (CVE-2011-2986)    

  - A heap overflow vulnerability exists in WebGL's ANGLE
    library. (CVE-2011-2987)

  - A buffer overflow vulnerability exists in WebGL when
    using an overly long shader program. (CVE-2011-2988)

  - Two errors exist related to Content Security Policy
    that can lead to information disclosure. (CVE-2011-2990)

  - An unspecified error exists that can allow unsigned
    JavaScript to call into a signed JAR and inherit the
    signed JAR's permissions and identity. (CVE-2011-2993)

  - There is an error in the implementation of the
    'window.location' JavaScript object when creating named
    frames. This can be exploited to bypass the same-origin
    policy and potentially conduct cross-site scripting
    attacks.(CVE-2011-2999)");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-29/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-38/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-11-270/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Firefox 6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport"); 

installs = get_kb_list("SMB/Mozilla/Firefox/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Firefox");

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'6.0', skippat:'^3\\.6\\.', severity:SECURITY_HOLE);
