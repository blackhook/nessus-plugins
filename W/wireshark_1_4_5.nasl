#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53473);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");

  script_cve_id("CVE-2011-1590", "CVE-2011-1591", "CVE-2011-1592");
  script_bugtraq_id(47392);
  script_xref(name:"EDB-ID", value:"17185");
  script_xref(name:"EDB-ID", value:"18145");
  script_xref(name:"Secunia", value:"44172");

  script_name(english:"Wireshark < 1.2.16 / 1.4.5 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The installed version of Wireshark is 1.2.x less than 1.2.16 or 1.4.x
less than 1.4.5.  Such versions are affected by the following
vulnerabilities :
  
  - A data type mismatch error exists in the function 
    'dissect_nfs_clientaddr4' in the file 'packet-nfs.c' of
    the NFS dissector and could lead to application crashes
    while decoding 'SETCLIENTID' calls. (5209) 
  
  - A use-after-free error exists in the file 
    'asn1/x509if/x509if.cnf' of the X.509if dissector that
    could lead to application crashes. (5754, 5793) 
  
  - An buffer overflow vulnerability exists in the file
    'packet-dect.c' of the DECT dissector that could allow
    arbitrary code execution. (5836)"
  );
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5209");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5754");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5793");
  script_set_attribute(attribute:"see_also", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5836");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-05.html");
  script_set_attribute(attribute:"see_also", value:"https://www.wireshark.org/security/wnpa-sec-2011-06.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.2.16.html");
  script_set_attribute(attribute:"see_also", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.5.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Wireshark version 1.2.16 / 1.4.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark packet-dect.c Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/18");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '1.4.0', 'max_version' : '1.4.4', 'fixed_version' : '1.4.5' },
  { 'min_version' : '1.2.0', 'max_version' : '1.2.15', 'fixed_version' : '1.2.16' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
