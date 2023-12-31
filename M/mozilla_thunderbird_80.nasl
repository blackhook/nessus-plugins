#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56753);
  script_version("1.10");
  script_cvs_date("Date: 2018/07/16 14:09:15");

  script_cve_id(
    "CVE-2011-3648",
    "CVE-2011-3649",
    "CVE-2011-3650",
    "CVE-2011-3651",
    "CVE-2011-3652",
    "CVE-2011-3653",
    "CVE-2011-3654",
    "CVE-2011-3655"
  );
  script_bugtraq_id(
    50591,
    50592,
    50593,
    50594,
    50595,
    50597,
    50600,
    50602
  );

  script_name(english:"Mozilla Thunderbird < 8.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 8.0 and thus, is
potentially affected by the following security issues :

  - Certain invalid sequences are not handled properly in
    'Shift-JIS' encoding and can allow cross-site scripting
    attacks. (CVE-2011-3648)

  - The addition of the 'Azure' graphics functionality re-
    introduced a cross-origin information disclosure issue
    previously described in CVE-2011-2986. (CVE-2011-3649)

  - Profiling JavaScript files with many functions can cause
    the application to crash. It may be possible to trigger
    this behavior even when the debugging APIs are not being
    used. (CVE-2011-3650)

  - Multiple memory safety issues exist. (CVE-2011-3651)

  - An unchecked memory allocation failure can cause the
    application to crash. (CVE-2011-3652)

  - An issue with WebGL graphics and GPU drivers can allow
    allow cross-origin image theft. (CVE-2011-3653)

  - An error exists related to SVG 'mpath' linking to a
    non-SVG element and can result in potentially
    exploitable application crashes. (CVE-2011-3654)

  - An error in internal privilege checking can allow
    web content to obtain elevated privileges.
    (CVE-2011-3655)");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-47/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-48/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-49/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-50/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-51/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-52/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'8.0', skippat:'^3\\.1\\.', severity:SECURITY_HOLE);