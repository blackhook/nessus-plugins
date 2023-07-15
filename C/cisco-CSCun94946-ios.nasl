#TRUSTED aafa75a5d3bd09fbf39e8c67ce80dff3f20ab18c54fb99f76d3f8d08f84f1c5b4ab48926c06e972a5d34509e97dfdad47aaef78ff626bfd7e50c88c90a6b8b44f52ef27e02e59e0b27dd862f552bdadee7b4c031074ef395643dc280224e2ecd53ca2eaa982f85ecead014fef48124b5a17d1c46788ce00c9ebc7ddb1eb50345fff93ed0b34f64e5b8fd27fb569a72e318e5917f11db6276d8522841aa9527671a0f9c26d8dce940dc40da1ac8bc7cbc8374934c61a1a183d1571a3c505b3855e0ae8aeabc253a8bc9844a7a7808165e2944a66b217d82b7ac3476a6824060cd89b9bfdcdce36a0db860d2d474b12e36a39032be578a2a1487b0888de452113ec66fee7e8055cf6f045994ba0b4724f9be578b0f924356f558e2ac03e313c82f06b184911a4c82234c015c1cc5211cf1a292833435043b0aa7ed743700aa9f4424b9ad703006bec86da4c3a1bd09b2190ce25bf24cff497ff3efa6657c3be2f2d5d57629b995a4f6c6dc1e3bc7b2a62d02a4e3375e59ad11287bae3d78cafa823ecb6d8668e302199728bb10eedf9a6b49bcebce3a0609f4506cd8750da83515939295c0f5d543e8221ea053d6c913a363882fe4a46fc2fc162a26e0b97a20c9a90d2f084ea04616ef0967389dfeb09b40542e071b09f6725b5f779e6dbbaa72266b3d0307f0c35806d3ab85ed1da161586d0bd374be46ae0e0acb74b2a09727
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91854);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2014-2146");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun94946");

  script_name(english:"Cisco IOS Zone-Based Firewall Feature Security Bypass (CSCun94946)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a security bypass vulnerability
in the Zone-Based Firewall feature due to insufficient zone checking
for traffic belonging to existing sessions. An unauthenticated, remote
attacker can exploit this, by injecting spoofed traffic that matches
existing connections, to bypass security access restrictions on the
device and gain access to resources.");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCun94946");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=39129");
  # https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/15-5m-and-t/release/notes/15-5m-and-t-book.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33d9e76a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.
Alternatively, disable the Zone-Based Firewall feature according to
the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2146");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;
override = 0;
fix_ver_s = "15.5(2)S";
fix_ver_t = "15.5(2)T";

if (cisco_gen_ver_compare(a:ver, b:fix_ver_s) < 0) flag++;
else if (cisco_gen_ver_compare(a:ver, b:fix_ver_t) < 0) flag++;

if (flag > 0 && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  # verify zone-based firewall is enabled
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(pattern:"^zone security \S+", multiline:TRUE, string:buf)) { flag = 1; }
    if (preg(pattern:"^zone-member security \S+", multiline:TRUE, string:buf)) { flag = 1; }
  }
  else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCun94946' +
      '\n  Installed release : ' + ver +
      '\n  Fix releases      : See solution.' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
