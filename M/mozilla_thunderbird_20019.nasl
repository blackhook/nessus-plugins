#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35287);
  script_version("1.16");

  script_cve_id(
    "CVE-2008-5500", 
    "CVE-2008-5503", 
    "CVE-2008-5506", 
    "CVE-2008-5507",
    "CVE-2008-5508", 
    "CVE-2008-5510", 
    "CVE-2008-5511", 
    "CVE-2008-5512"
  );
  script_bugtraq_id(32882);

  script_name(english:"Mozilla Thunderbird < 2.0.0.19 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities."  );
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird is earlier than 2.0.0.19.  Such
versions are potentially affected by the following security issues :

  - There are several stability bugs in the browser engine
    that could lead to crashes with evidence of memory
    corruption. (MFSA 2008-60)

  - XBL bindings can be used to read data from other
    domains. (MFSA 2008-61)

  - Sensitive data could be disclosed in an XHR response 
    when an XMLHttpRequest is made to a same-origin 
    resource, which 302 redirects to a resource in a 
    different domain. (MFSA 2008-64)

  - A website may be able to access a limited amount of
    data from a different domain by loading a same-domain
    JavaScript URL, which redirects to an off-domain target
    resource containing data that is not parsable as
    JavaScript. (MFSA 2008-65)

  - Errors arise when parsing URLs with leading whitespace
    and control characters. (MFSA 2008-66)

  - An escaped null byte is ignored by the CSS parser and
    treated as if it was not present in the CSS input
    string. (MFSA 2008-67)

  - XSS and JavaScript privilege escalation are possible.
    (MFSA 2008-68)"  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-60/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-61/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-64/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-65/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-66/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-67/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2008-68/"
  );
  # https://website-archive.mozilla.org:443/www.mozilla.org/thunderbird_releasenotes/en-US/thunderbird/2.0.0.19/releasenotes/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?35fe47a6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mozilla Thunderbird 2.0.0.19 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 200, 264, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/02");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/12/16");
 script_cvs_date("Date: 2018/11/15 20:50:27");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'2.0.0.19', severity:SECURITY_HOLE);