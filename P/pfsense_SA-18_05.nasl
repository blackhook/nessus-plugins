#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119886);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/05 23:25:05");

  script_cve_id(
    "CVE-2018-6920",
    "CVE-2018-6921",
    "CVE-2018-8897"
  );

  script_name(english:"pfSense 2.3.x < 2.3.5-p2 / 2.4.x < 2.4.3-p1 Multiple Vulnerabilities (SA-18_04 / SA-18_05)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is a version 2.3.x prior to 2.3.5-p2 or 2.4.x prior to
2.4.3-p1. It is, therefore, affected by multiple vulnerabilities:

 - In FreeBSD before 11.1-STABLE(r332066) and 11.1-RELEASE-p10, due
   to insufficient initialization of memory copied to userland in 
   the network subsystem, small amounts of kernel memory may be 
   disclosed to userland processes. Unprivileged authenticated 
   local users may be able to access small amounts of privileged 
   kernel data. (CVE-2018-6921)
   
 - A statement in the System Programming Guide of the Intel 64 and 
   IA-32 Architectures Software Developer's Manual (SDM) was 
   mishandled in the development of some or all operating-system 
   kernels, resulting in unexpected behavior for #DB exceptions that
    could lead to local privilege escalation. (CVE-2018-8897)");
  # https://www.pfsense.org/security/advisories/pfSense-SA-18_05.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74fc852c");
  # https://www.pfsense.org/security/advisories/pfSense-SA-18_04.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3dd41163");
  # https://www.netgate.com/docs/pfsense/releases/2-3-5-p2-new-features-and-changes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a4454c4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.3.5-p2 / 2.4.3-p1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8897");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pfsense:pfsense");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bsdperimeter:pfsense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pfsense_detect.nbin");
  script_require_keys("Host/pfSense");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

if (!get_kb_item("Host/pfSense")) audit(AUDIT_HOST_NOT, "pfSense");

app_info = vcf::pfsense::get_app_info();
constraints = [
  { "min_version" : "2.4.0", "fixed_version" : "2.4.3-p1"},
  { "min_version" : "2.3.0", "fixed_version" : "2.3.5-p2"}
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
