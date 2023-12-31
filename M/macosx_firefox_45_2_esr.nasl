#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91544);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/19");

  script_cve_id(
    "CVE-2016-2818",
    "CVE-2016-2819",
    "CVE-2016-2821",
    "CVE-2016-2822",
    "CVE-2016-2828",
    "CVE-2016-2831"
  );
  script_bugtraq_id(91072, 91074, 91075);
  script_xref(name:"MFSA", value:"2016-49");
  script_xref(name:"MFSA", value:"2016-50");
  script_xref(name:"MFSA", value:"2016-51");
  script_xref(name:"MFSA", value:"2016-52");
  script_xref(name:"MFSA", value:"2016-56");
  script_xref(name:"MFSA", value:"2016-58");

  script_name(english:"Firefox ESR 45.x < 45.2 Multiple Vulnerabilities (Mac OS X)");
  script_summary(english:"Checks the version of Firefox.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Mac OS X host is
45.x prior to 45.2. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-2818)

  - An overflow condition exists that is triggered when
    handling HTML5 fragments in foreign contexts (e.g.,
    under <svg> nodes). An unauthenticated, remote attacker
    can exploit this to cause a heap-based buffer overflow,
    resulting in the execution of arbitrary code.
    (CVE-2016-2819)

  - A use-after-free error exists that is triggered when
    deleting DOM table elements in 'contenteditable' mode.
    An unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-2821)

  - A spoofing vulnerability exists due to improper handling
    of SELECT elements. An unauthenticated, remote attacker
    can exploit this to spoof the contents of the address
    bar. (CVE-2016-2822)

  - A use-after-free error exists that is triggered when
    destroying the recycle pool of a texture used during the
    processing of WebGL content. An unauthenticated, remote
    attacker can exploit this to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2016-2828)

  - A flaw exists that is triggered when handling paired
    fullscreen and pointerlock requests in combination with
    closing windows. An unauthenticated, remote attacker can
    exploit this to create an unauthorized pointerlock,
    resulting in a denial of service condition.
    Additionally, an attacker can exploit this to conduct
    spoofing and clickjacking attacks. (CVE-2016-2831)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-49/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-50/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-51/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-52/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-56/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-58/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Firefox ESR version 45.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2828");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_firefox_installed.nasl");
  script_require_keys("MacOSX/Firefox/Installed");

  exit(0);
}

include("mozilla_version.inc");

kb_base = "MacOSX/Firefox";
get_kb_item_or_exit(kb_base+"/Installed");

version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);

is_esr = get_kb_item(kb_base+"/is_esr");
if (isnull(is_esr)) audit(AUDIT_NOT_INST, "Mozilla Firefox ESR");

mozilla_check_version(product:'firefox', version:version, path:path, esr:TRUE, fix:'45.2', min:'45.0', severity:SECURITY_WARNING);
