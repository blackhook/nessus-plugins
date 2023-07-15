#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119887);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id(
    "CVE-2018-3620",
    "CVE-2018-3646",
    "CVE-2018-6922",
    "CVE-2018-6923",
    "CVE-2018-6924",
    "CVE-2018-14526",
    "CVE-2018-15473",
    "CVE-2018-16055"
  );

  script_name(english:"pfSense 2.3.x <= 2.3.5-p2 / 2.4.x < 2.4.4 Multiple Vulnerabilities (SA-18_06 / SA-18_07 / SA-18_08)");
  script_summary(english:"Checks the version of pfSense.");

  script_set_attribute(attribute:"synopsis", value:
"The remote firewall host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote pfSense
install is a version 2.3.x  prior or equal to  2.3.5-p2 or 2.4.x 
prior to 2.4.3-p1. It is, therefore, affected by multiple
vulnerabilities:

 - Systems with microprocessors utilizing speculative execution and 
   address translations may allow unauthorized disclosure of 
   information residing in the L1 data cache to an attacker with 
   local user access via a terminal page fault and a side-channel 
   analysis. (CVE-2018-3620)
   
 - An authenticated command injection vulnerability exists in 
   status_interfaces.php via dhcp_relinquish_lease() in pfSense
   before 2.4.4. This allows an authenticated WebGUI user with 
   privileges for the affected page to execute commands in the 
   context of the root user when submitting a request to relinquish
   a DHCP lease for an interface which is configured to obtain its
   address via DHCP. (CVE-2018-16055)
   
 -  a denial of service vulnerability exists in the ip fragment 
    reassembly code due to excessive system resource consumption. 
    This issue can allow a remote attacker who is able to send
    arbitrary ip fragments to cause the machine to consume excessive
    resources. (CVE-2018-6923)");
  # https://www.pfsense.org/security/advisories/pfSense-SA-18_06.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c44a2d3c");
  # https://www.pfsense.org/security/advisories/pfSense-SA-18_07.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b33cf0ad");
  # https://www.pfsense.org/security/advisories/pfSense-SA-18_08.webgui.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db4f32a9");
  # https://www.netgate.com/docs/pfsense/releases/2-4-4-new-features-and-changes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d4d989a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to pfSense version 2.4.4 or later, or apply patches as noted
in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16055");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/09");
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
  {"min_version":"2.3.0", "max_version":"2.3.5-p2", "fixed_version":"2.4.4"},
  {"min_version":"2.4.0", "max_version":"2.4.3-p1", "fixed_version":"2.4.4"}
];

vcf::pfsense::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  flags:{xss:TRUE}
);
