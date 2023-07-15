#TRUSTED 5141535a8242ddd2063164b6e514e2c70a7401958b56f6d1d3627ef5a825af0d7823a81da35d860c6b76be6841e08f18eb560fe31a4de7129a36852651c9890e835973a7a32c3f920f6e904de5afd9ff0ab846ce5ae0481e22005995b5c704faf0bd6815f1b12800a3c3f8632a577acb2ca42e64f78cd24cc1b76a34a188e2bc92ebc49304143a513c51efd4eea786a11d61dbdc4b046af698eaea634e1287eb58d51555b4e315b651797e76dffd9c9d5768f6af420f97c38175b84788b325c95503b19c3e3ffae87fda808c9d68bec54134acc2e7b2eaf5a4e616f5ac012f0413a4de735f0e8e1074fe983fd4127643435b11173c5d8bc90cee4d1364628479c1049243f5ad6e7cca737f269a5d24ecd329198c17e89c200046abe27cbd761237bd940629f0b5062805389d7c95537fc1b0757eb38f753dcb0c79fc86b7154d05c94a5c09f5b9d5e195704d0495a596b5785c790bca9c7eaa2fb71c7933b2c5ed0b2b9b4725d5afb1e5d5e36780054a9feadc8cba7409dca9ba9e6cc4d584dd69f4c7a58ee1dcecb245a38a5cd49dade34cf89c1078e78a3f9203dcd207b38f77752003abcdc933c8e439fefacf37a09278075eacbe0630752afdd3faa6634b6fd7cc9508f514b961f02cf80250990db9c2bb82368ed726460ddf2edff924df1099148a9e7e249239f9ca9375fd086db125a3f68c25a2bdbb4780be103a500f
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20131002-iosxr.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(71437);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2013-5503");
  script_bugtraq_id(62770);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue69413");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131002-iosxr");

  script_name(english:"Cisco IOS XR Software Memory Exhaustion Vulnerability (cisco-sa-20131002-iosxr)");
  script_summary(english:"Checks the IOSXR version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description", 
    value:
"Cisco IOS XR Software version 4.3.1 contains a vulnerability that could
result in complete packet memory exhaustion.  Successful exploitation
could render critical services on the affected device unable to allocate
packets resulting in a denial of service (DoS) condition.  Cisco has
released free software updates that address this vulnerability. 
Workarounds that mitigate this vulnerability are available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131002-iosxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b21028c");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131002-iosxr."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5503");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report = "";
override = 0;

cbi = "CSCue69413";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ( version == '4.3.1' ) flag++;

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp_brief", "show udp brief");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:":(161|162|123|646|514)", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + version + '\n';

  security_hole(port:port, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
