#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56336);
  script_version("1.9");
  script_cvs_date("Date: 2018/07/16 14:09:15");

  script_cve_id(
    "CVE-2011-2372",
    "CVE-2011-2995",
    "CVE-2011-2997",
    "CVE-2011-3000",
    "CVE-2011-3001",
    "CVE-2011-3005",
    "CVE-2011-3232"
  );
  script_bugtraq_id(
    49800,
    49808,
    49811,
    49837,
    49849,
    49850
  );

  script_name(english:"Mozilla Thunderbird < 7.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that may be affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 7.0 and thus, is
potentially affected by the following security issues :

  - If an attacker could trick a user into holding down the
    'Enter' key, via a malicious game, for example, a
    malicious application or extension could be downloaded
    and executed.(CVE-2011-2372, CVE-2011-3001)

  - Unspecified errors exist that can be exploited to
    corrupt memory. No additional information is available
    at this time. (CVE-2011-2995, CVE-2011-2997)

  - A weakness exists when handling the 'Location' header.
    This can lead to response splitting attacks when
    visiting a vulnerable web server. The same fix has been
    applied to the headers 'Content-Length' and
    'Content-Disposition'. (CVE-2011-3000)

  - A use-after-free error exists when parsing OGG headers.
    (CVE-2011-3005)

  - There is an unspecified error within the YARR regular
    expression library that can be exploited to corrupt
    memory. (CVE-2011-3232)");

  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-36/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-39/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-40/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-42/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2011-44/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/29");

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

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'7.0', skippat:'^3\\.1\\.', severity:SECURITY_HOLE);