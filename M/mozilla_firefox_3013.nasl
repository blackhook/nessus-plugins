#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40478);
  script_version("1.20");

  script_cve_id(
    "CVE-2009-2404", 
    "CVE-2009-2408", 
    "CVE-2009-2654", 
    "CVE-2009-2662",
    "CVE-2009-2663", 
    "CVE-2009-2664"
  );
  script_bugtraq_id(35803, 35888, 35891, 35927, 36018);
  script_xref(name:"Secunia", value:"36001");
  script_xref(name:"Secunia", value:"36088");

  script_name(english:"Firefox < 3.0.13 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Firefox");

  script_set_attribute(  attribute:"synopsis",  value:
"The remote Windows host contains a web browser that is
affected by multiple flaws."  );
  script_set_attribute(  attribute:"description",  value:
"The installed version of Firefox is earlier than 3.0.13.  Such
versions are potentially affected by the following security issues :

  - The browser can be fooled into trusting a malicious SSL
    server certificate with a null character in the host name.
    (MFSA 2009-42)

  - A heap overflow in the code that handles regular
    expressions in certificate names can lead to
    arbitrary code execution. (MFSA 2009-43)

  - The location bar and SSL indicators can be spoofed
    by calling window.open() on an invalid URL. A remote
    attacker could use this to perform a phishing attack.
    (MFSA 2009-44)

  - Unspecified JavaScript-related vulnerabilities can lead
    to memory corruption, and possibly arbitrary execution
    of code. (MFSA 2009-45)"  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-42/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-43/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-44/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/en-US/security/advisories/mfsa2009-45/"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Firefox 3.0.13 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 310, 399);
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/04");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/08/01");
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

mozilla_check_version(installs:installs, product:'firefox', esr:FALSE, fix:'3.0.13', severity:SECURITY_HOLE);