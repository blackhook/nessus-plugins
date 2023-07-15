#TRUSTED 66f3f38190613c6b0a569bf7091606d4d16f41f22744d3e6a8389d895b2b54a072a53f733178ea4d89a49636ae6614c431d25f44b2d53ffc48b6d535ec31a05e5f94de7903d8ceda5a082cfca39b55f67dccb97e34722b233682735ec22692196ef8fdc5ada2fcfec995e142a7e0e725c19c75c65402bbde8164128aa7e1f534ee0453f8eb8b9610695809d199943e9eaa72bf8801d62837539c60e78cda54f5cb091a87fcdeab96642c1f300a891f69b941d862804fdf2a49e6b309f5ca0f43dc051a171b44098b86494423efb51eaba315bac7bff1d98b15797463c2f53945e078e0a97225d64ac199a0f81b06544338be0876894b4f646c19d12de59dda03352c1b507dadc697ab80b7a93dadd9681baa8d24162bd78f45d3a99299fa34fb4ee05efe34dba83b2cb5434a3ad079feb7b51c060fe4c6925dae64b3f28cce91d2d97fc4dffa9fe98eb8bebaf385739b5c9b85a58b90ac2949ce53f39ef41e0c0482f86adf77c7c2584117c66520b25341fa4511f799cf1ef1cd4d3e40dde6ecbd33ecbaac3d28ab2850b4e67da428589668db4fbcc0e33d486b3c3ce6f8524caa8e112ba18618bae3cc39a9f13ca8efac058138c9613bdac4521ad93bd7869710f1df2509492063eeb48fa752eb7ed0a5454173d28dcc4bc7ab2efddf76a00047da00351779ec29da1d00150078e3183fee9104a08ad050bae13f80acfa78a9
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132244);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/19");

  script_cve_id("CVE-2019-1607");
  script_bugtraq_id(107393);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi01416");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190306-nxos-cmdinj-1607");

  script_name(english:"Cisco NX-OS Software CLI Command Injection Vulnerability (CVE-2019-1607)");
  script_summary(english:"Checks the version of Cisco NX-OS Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco NX-OS Software is affected by a vulnerability in the CLI of Cisco NX-OS
Software that could allow an authenticated, local attacker to execute arbitrary commands on the underlying operating
system of an affected device.The vulnerability is due to insufficient validation of arguments passed to certain CLI
commands.  An attacker could exploit this vulnerability by including malicious input as the argument of an affected
command.  A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating
system with elevated privileges. An attacker would need valid administrator credentials to exploit this vulnerability.
(CVE-2019-1607)

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190306-nxos-cmdinj-1607
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?04cdcf54");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-70757");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi01416");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvi01416");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1607");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('Nexus' >!< product_info.device || product_info.model !~ "7[07][0-9][0-9]")
  audit(AUDIT_HOST_NOT, "affected");

version_list=make_list(
  '8.2(2)',
  '8.2(1)',
  '8.1(2a)',
  '8.1(2)',
  '8.1(1)',
  '8.0(1)',
  '7.3(2)D1(3a)',
  '7.3(2)D1(3)',
  '7.3(2)D1(2)',
  '7.3(2)D1(1)',
  '7.3(1)D1(1)',
  '7.3(0)DX(1)',
  '7.3(0)D1(1)',
  '7.2(2)D1(2)',
  '7.2(2)D1(1)',
  '7.2(1)D1(1)',
  '7.2(0)D1(1)',
  '6.2(8b)',
  '6.2(8a)',
  '6.2(8)',
  '6.2(6b)',
  '6.2(6a)',
  '6.2(6)',
  '6.2(2a)',
  '6.2(20a)',
  '6.2(20)',
  '6.2(2)',
  '6.2(18)',
  '6.2(16)',
  '6.2(14)',
  '6.2(12)',
  '6.2(10)'
);

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvi01416'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list, switch_only:TRUE);
