#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35978);
  script_version("1.19");

  script_cve_id(
    "CVE-2009-0040",
    "CVE-2009-0352",
    "CVE-2009-0353",
    "CVE-2009-0357",
    "CVE-2009-0652",
    "CVE-2009-0771",
    "CVE-2009-0772",
    "CVE-2009-0773",
    "CVE-2009-0774",
    "CVE-2009-0776"
  );
  script_bugtraq_id(33598, 33827, 33837, 33990);
  if (NASL_LEVEL >= 3000)
  {
  }

  script_name(english:"SeaMonkey < 1.1.15 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute( attribute:"synopsis", value:
"A web browser on the remote host is affected by multiple
vulnerabilities."  );
  script_set_attribute( attribute:"description",  value:
"The installed version of SeaMonkey is earlier than 1.1.15.  Such
versions are potentially affected by the following security issues :

  - There are several stability bugs in the browser engine
    that may lead to crashes with evidence of memory 
    corruption. (MFSA 2009-01)

  - Cookies marked HTTPOnly are readable by JavaScript via
    the 'XMLHttpRequest.getResponseHeader' and 
    'XMLHttpRequest.getAllResponseHeaders' APIs. 
    (MFSA 2009-05)

  - By exploiting stability bugs in the browser engine, it 
    might be possible for an attacker to execute arbitrary 
    code on the remote system under certain conditions. 
    (MFSA 2009-07)

  - It may be possible for a website to read arbitrary XML
    data from another domain by using nsIRDFService and a 
    cross-domain redirect. (MFSA 2009-09)

  - Vulnerabilities in the PNG libraries used by Mozilla
    could be exploited to execute arbitrary code on the 
    remote system. (MFSA 2009-10)

  - A URI spoofing vulnerability exists because the 
    application fails to adequately handle specific 
    characters in IDN subdomains. (MFSA 2009-15)"  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-01/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-05/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-07/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-09/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-10/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-15/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to SeaMonkey 1.1.15 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 200, 264, 399);
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/20");
 script_cvs_date("Date: 2018/07/27 18:38:15");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
 
  script_copyright(english:"This script is Copyright (C) 2009-2018 Tenable Network Security, Inc.");
 
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");

  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'1.1.15', severity:SECURITY_HOLE);