#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70880);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id(
    "CVE-2009-4536",
    "CVE-2010-0296",
    "CVE-2011-0536",
    "CVE-2011-1071",
    "CVE-2011-1095",
    "CVE-2011-1658",
    "CVE-2011-1659"
  );
  script_bugtraq_id(37519, 46563, 47370);
  script_xref(name:"EDB-ID", value:"15274");
  script_xref(name:"VMSA", value:"2011-0009");
  script_xref(name:"VMSA", value:"2011-0012");

  script_name(english:"ESXi 5.0 < Build 515841 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.0 host is affected by multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.0 host is affected by the following security
vulnerabilities :

  - A security bypass vulnerability exists in the e1000
    driver in the Linux kernel due to improper handling of
    Ethernet frames that exceed the MTU. An unauthenticated,
    remote attacker can exploit this, via trailing payload
    data, to bypass packet filters. (CVE-2009-4536)

  - An error exists in the file misc/mntent_r.c that could
    allow a local attacker to cause denial of service
    conditions. (CVE-2010-0296)

  - An error exists related to glibc, the dynamic linker
    and '$ORIGIN' substitution that could allow privilege
    escalation. (CVE-2011-0536)

  - An error exists in the function 'fnmatch' in the file
    posix/fnmatch.c that could allow arbitrary code
    execution. (CVE-2011-1071)

  - An error exists in the file locale/programs/locale.c
    related to localization environment variables that
    could allow privilege escalation. (CVE-2011-1095)

  - An error exists related to glibc, the dynamic linker
    and 'RPATH' that could allow privilege escalation.
    (CVE-2011-1658)

  - An error exists in the function 'fnmatch' related to
    UTF-8 string handling that could allow privilege
    escalation. (CVE-2011-1659)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2011-0012.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2011-0009.html");
  # https://kb.vmware.com/selfservice/microsites/search.do?cmd=displayKC&externalId=2007671
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c402a9a2");
  # https://kb.vmware.com/selfservice/microsites/search.do?cmd=displayKC&externalId=2007673
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?635686b4");
  # https://kb.vmware.com/selfservice/microsites/search.do?cmd=displayKC&externalId=2007680
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fce8c282");
  script_set_attribute(attribute:"solution", value:
"Apply patches ESXi500-201112401-SG and ESXi500-201112403-SG.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0296");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is (C) 2013-2019 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 5.0" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.0");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 515841;

if (build < fixed_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host has "+ver+" build "+build+" and thus is not affected.");
