#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80524);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id(
    "CVE-2014-8634",
    "CVE-2014-8635",
    "CVE-2014-8638",
    "CVE-2014-8639"
  );
  script_bugtraq_id(
    72046,
    72047,
    72049,
    72050
  );

  script_name(english:"Mozilla Thunderbird < 31.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is
prior to 31.4. It is, therefore, affected by the following
vulnerabilities :

  - Multiple unspecified memory safety issues exist within
    the browser engine. (CVE-2014-8634, CVE-2014-8635)

  - A flaw exists in 'navigator.sendBeacon()' in which it
    does not follow the cross-origin resource sharing
    specification. This results in requests from
    'sendBeacon()' lacking an 'origin' header. This allows
    malicious sites to perform XSRF attacks. (CVE-2014-8638)

  - A flaw exists when receiving 407 Proxy Authentication
    responses with a 'set-cookie' header. This can allow
    a session-fixation attack. (CVE-2014-8639)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-01/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-03/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-04/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Thunderbird 31.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8635");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'31.4', min:'31.0', severity:SECURITY_HOLE, xss:FALSE, xsrf:TRUE);
