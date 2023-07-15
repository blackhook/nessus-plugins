#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44660);
  script_version("1.20");

  script_cve_id(
    "CVE-2009-1571",
    "CVE-2009-3988",
    "CVE-2010-0159",
    "CVE-2010-0160",
    "CVE-2010-0162",
    "CVE-2010-0167",
    "CVE-2010-0169",
    "CVE-2010-0171",
    "CVE-2010-0179"
  );
  script_bugtraq_id(
    38285, 
    38286, 
    38287, 
    38288, 
    38289, 
    38922, 
    38946, 
    39124
  );
  script_xref(name:"Secunia", value:"37242");

  script_name(english:"SeaMonkey < 2.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains a web browser that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.0.3.  Such
versions are potentially affected by the following security issues :

  - Multiple crashes can result in arbitrary code execution.
    (MFSA 2010-01)

  - The implementation of 'Web Workers' contained an error 
    in its handling of array data types when processing 
    posted messages. (MFSA 2010-02)

  - The HTML parser incorrectly frees used memory when
    insufficient space is available to process remaining
    input. (MFSA 2010-03)

  - A cross-site scripting issue exists due to 
    'window.dialogArguments' being readable cross-domain.
    (MFSA 2010-04)

  - A cross-site scripting issue exists when using SVG 
    documents and binary Content-Type. (MFSA 2010-05)

  - Multiple crashes can result in arbitrary code execution.
    (MFSA 2010-11)

  - A cross-site scripting issue when using 
    'addEventListener' and 'setTimeout' on a wrapped object.
    (MFSA 2010-12)

  - It is possible to corrupt a user's XUL cache. 
    (MFSA 2010-14)
    
  - The XMLHttpRequestSpy module in the Firebug add-on
    exposes an underlying chrome privilege escalation
    vulnerability. (MFSA 2010-21)");
  script_set_attribute(attribute:"see_also",value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-01/");
  script_set_attribute(attribute:"see_also",value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-02/");
  script_set_attribute(attribute:"see_also",value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-03/");
  script_set_attribute(attribute:"see_also",value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-04/");
  script_set_attribute(attribute:"see_also",value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-05/");
  script_set_attribute(attribute:"see_also",value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-11/");
  script_set_attribute(attribute:"see_also",value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-12/");
  script_set_attribute(attribute:"see_also",value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-14/");
  script_set_attribute(attribute:"see_also",value:"https://www.mozilla.org/en-US/security/advisories/mfsa2010-21/");
  script_set_attribute(attribute:"solution",value:"Upgrade to SeaMonkey 2.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 94, 264, 399);
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/02/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/02/17");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/02/18");
 script_cvs_date("Date: 2018/07/27 18:38:15");
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

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.0.3', severity:SECURITY_HOLE);