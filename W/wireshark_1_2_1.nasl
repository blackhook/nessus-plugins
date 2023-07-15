#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40335);
  script_version("1.15");

  script_cve_id(
    "CVE-2009-2559",
    "CVE-2009-2560",
    "CVE-2009-2561",
    "CVE-2009-2562",
    "CVE-2009-2563"
  );
  script_bugtraq_id(35748);
  script_xref(name:"Secunia", value:"35884");

  script_name(english:"Wireshark / Ethereal 0.9.2 to 1.2.0 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(  attribute:"synopsis",  value:
"The remote host has an application that is affected by multiple
vulnerabilities."  );
  script_set_attribute( attribute:"description", value:
"The installed version of Wireshark or Ethereal is affected by
multiple issues :

  - The IPMI dissector could overrun a buffer. (Bug 3559)

  - The AFS dissector could crash. (Bug 3564)

  - The Infiniband dissector could crash on some platforms.

  - The Bluetooth L2CAP dissector could crash. (Bug 3572)

  - The RADIUS dissector could crash. (Bug 3578)

  - The MIOP dissector could crash. (Bug 3652)

  - The sFlow dissector could use excessive CPU and memory.
    (Bug 3570)

These vulnerabilities could result in a denial of service, or
possibly arbitrary code execution.  A remote attacker could exploit
these issues by tricking a user into opening a maliciously crafted
capture file.  Additionally, if Wireshark is running in promiscuous
mode, one of these issues could be exploited remotely (from the same
network segment)."  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3564"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=3570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2009-04.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.2.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/09");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2023 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");
  
  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Wireshark', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.9.2', 'max_version' : '1.2.0', 'fixed_version' : '1.2.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
