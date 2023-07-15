#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102018);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/20");

  script_cve_id(
    "CVE-2017-6746",
    "CVE-2017-6748",
    "CVE-2017-6749",
    "CVE-2017-6750",
    "CVE-2017-6751"
  );
  script_bugtraq_id(
    99875,
    99877,
    99918,
    99924
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd88862");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd88855");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd88865");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve06124");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd88863");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170719-wsa1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170719-wsa2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170719-wsa3");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170719-wsa4");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170719-wsa5");

  script_name(english:"Cisco Web Security Appliance Multiple Vulnerabilities");
  script_summary(english:"Checks the Cisco Web Security Appliance (WSA) version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Web Security
Appliance (WSA) device is affected by one or more vulnerabilities :

  - An unspecified flaw exists in the web-based interface
    due to improper validation of user-supplied input. An
    authenticated, remote attacker who has valid
    administrator credentials can exploit this vulnerability
    to inject arbitrary commands and thereby elevate
    privileges from administrator to root. (CVE-2017-6746)

  - An unspecified flaw exists in the CLI parser due to
    improper sanitization of user-supplied input. A local
    attacker can exploit this to inject arbitrary commands
    and thereby escape the CLI subshell and gain root
    privileges. (CVE-2017-6748)

  - A stored cross-site scripting (XSS) vulnerability exists
    in the web-based management interface due to improper
    validation of user-supplied input before returning it to
    users. An authenticated, remote attacker can exploit
    this, by convincing a user to follow a specially
    crafted link, to execute arbitrary script code in a
    user's browser session. (CVE-2017-6749)

  - A security vulnerability exists due to WSA being
    installed with a user account that has a default and
    static password. An unauthenticated, remote attacker can
    exploit this to gain privileged access to certain
    portions of the web-based management interface, allowing
    the attacker to download reports or disclose the
    device's serial number. (CVE-2017-6750)

  - A security bypass vulnerability exists in the web proxy
    functionality due to a failure to deny traffic that is
    forwarded from the web proxy interface to the
    administrative management interface of a device. An
    unauthenticated, remote attacker can exploit this issue
    to bypass access restrictions by sending a specially
    crafted stream of HTTP or HTTPS traffic to the web proxy
    interface of an affected device. (CVE-2017-6451)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170719-wsa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?142f72cc");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170719-wsa2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31a4794a");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170719-wsa3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fe44129");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170719-wsa4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c672cb4");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170719-wsa5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0048c64e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd88862");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd88855");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd88865");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve06124");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd88863");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs
CSCvd88862, CSCvd88855, CSCvd88865, CSCve06124, and CSCvd88863.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-6746");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("cisco_func.inc");


display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/Version');


if(ver ==  "10.0.0" ||
   ver == "10.0.0.232" ||
   ver == "10.0.0.233" ||
   ver == "10.0" ||
   ver == "10.1.0" ||
   ver == "10.1.0.204" ||
   ver == "10.1.1" ||
   ver == "10.1.1.230" ||
   ver == "10.1.1.234" ||
   ver == "10.1" ||
   ver == "10.5.0" ||
   ver == "10.5.0.358" ||
   ver == "10.5.1" ||
   ver == "10.5" ||
   ver == "11.0.0" ||
   ver == "11.0.0.613" ||
   ver == "11.0.0.641" ||
   ver == "11.0" ||
   ver == "9.0.0" ||
   ver == "9.0.0.162" ||
   ver == "9.0.0.193" ||
   ver == "9.0.0.485" ||
   ver == "9.0" )
{
  security_report_cisco(
    port:      0,
    severity:  SECURITY_HOLE,
    version:   ver,
    bug_id:    "CSCvd88862, CSCvd88855, CSCvd88865, CSCve06124, CSCvd88863",
    fix:       "See advisory",
    xss:       TRUE
  );
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);
