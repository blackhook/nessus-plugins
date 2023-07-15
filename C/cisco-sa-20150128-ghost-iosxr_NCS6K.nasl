#TRUSTED 2bab4c2e8dd04360f36373efc45585d7a04f28fe49a09709edf37a96992be6a1071b8be5caf474f7b3891f9fd6d7418be0ee05638307846d1ef936233876d0e5ed93e215a8147d9f425a515c7dd28f89062aa13a479e59c18d0864c745e07a249a7b620fef8936000a2e61f44e457b072c7d5645b3878d09103689fd374339b6c44ff5141b708d9b300fbbc24254ce0c13d57206283e2fbe481f11d3761e4fcd4b41914d83ecbcae5cc9bcbb104b76f7ef33e9376832018894203162eb2867a0dea2d3c1060d15a7f79b12a9f2f74c21e9fbec9c109f4129b9a23a31631d019dd76957e9e038b0a67cb06c56c9482f76cccfc4f872e6fc2c051812e2afce2ecf6aabb14714cef10a104181c3a419b19c41fd3d1a28a7dd39e87da5510f5d2d53b7eb7d2f0f7b646bd87728f1b6f89b694e3179aae4269b473fa62f9f612a807a880912b39b6e13cc9542ce719236787ddfdd10d1fe31eef832c6d2924916a4f465805619909dd6d5b0ac42c1ef4618e6f9460cf26673cb0220147490bedf825387fe826378f8f3ebabccd7f87d9b7fc15b932462020baaf1914bf03e38d0b6b9f24ae8cbcf450a4c4fe539e1b09603a9deb4b2df8db292c5da66c4d105048714ae272f6a2c2650e4b815be6f4fd43d0f9b451349a398aadd6baa8e303a642d75abf3cbfa8d84ab3b98aea90ef77e59922a6390886844add7f0e5ce1a9b54d9ec
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81596);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus69517");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150128-ghost");

  script_name(english:"Cisco IOS XR GNU C Library (glibc) Buffer Overflow (GHOST)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS XR software
that is potentially affected by a heap-based buffer overflow
vulnerability in the GNU C Library (glibc) due to improperly
validated user-supplied input to the __nss_hostname_digits_dots(),
gethostbyname(), and gethostbyname2() functions. This allows a remote
attacker to cause a buffer overflow, resulting in a denial of service
condition or the execution of arbitrary code.

Note that this issue only affects Cisco Network Convergence System
6000 Series routers.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCus69517");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150128-ghost
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd2144f8");
  # https://www.qualys.com/research/security-advisories/GHOST-CVE-2015-0235.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7a6ddbd");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCus69517.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0235");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device_name = "Cisco Network Convergence System 6000 Series Router";

# Check model
model = get_kb_item("CISCO/model");
if(
  !isnull(model)
  &&
  tolower(model) !~ "ncs(6008|6k)"
) audit(AUDIT_HOST_NOT, device_name);

# First source failed, try another source
if (isnull(model))
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if (
    "NCS6008" >!< model
    &&
    "NCS6k" >!< model
  ) audit(AUDIT_HOST_NOT, device_name);
}

# Check rough version
# 5.2.x / 5.4.x
version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if (version !~ "^5\.[24]\.")
  audit(AUDIT_HOST_NOT, device_name + " 5.2.x / 5.4.x");

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

# Affected :
# 5.2.4.BASE, i.e., 5.2.4
# 5.4.0.BASE, i.e., 5.4.0
if (
  version == "5.2.4"
  ||
  version == "5.4.0"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCus69517' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
}
else audit(AUDIT_INST_VER_NOT_VULN, device_name, version);
