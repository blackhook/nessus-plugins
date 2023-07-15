#TRUSTED 03e3bbd9312ea760804cba54e1698da43c67a52680b2cc498d0faee9f654f750878f07e204e654f024659ffa3e44322b5bf41accffbab9d9434266d995b7583f2d861f430b87d5afcef63415f4e3453d416d09804995660cfb304a559f6afbef68fc52201790732d823dd5b1053b39c3a2ee8de7b5cba8e824781d194058f3707b8dace00bf056bc68aece13556cd26a90e2408ca0e64dfcb7f2d6c5d4566fb3e97c96715df88138b637fb4ed8aa6551b3b015d578f4d37f0002b759d496ef45e3878a59d5a2d8664d28dab1c944af488b68cba210ca5bd9061f1141c0941938cec4e1c7cc6cba7985c44ce4b757f2c3de877c66872be1a0353396533d82354a0a26b665b51d2af7b9c1fec9affdf1abe823695094b0a871f614408578a5aca4eebd10eb4f23b06153d558a57e3b1e2b965a9d68e3b3abf04907037a76abe0979b316a6ac7173db4001e64857c135eb45870a31c01ce57929118d7556fec5bc9e5f66ebba5c7bb224c080fb57f58278c58f998ef4b6b6a009fe67a6cb38fdffda419c177bb36b3425d62e040729754a1654a354d8cef48af31f9f08ba189ee4d27760af5f6a70371236af617260628c4ccf24ea282f91785d1ffed0fc14c17293190ebf34dc5be7bbee31cf4372c20fe4b208a56ca49a78a1ee8f1d8b1fb21c88166155f95fdbc3c30cfa0b58969586d0474761392b7bdcca71d7d2541028217
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91426);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id("CVE-2015-4595");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu93339");

  script_name(english:"Cisco ASA Cavium SDK TLS Incorrect Padding Acceptance Plaintext Disclosure (CSCuu93339)");
  script_summary(english:"Checks the ASA version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Adaptive Security Appliance (ASA) is missing a
vendor-supplied security patch. It is, therefore, affected by a flaw
in the TLS 1.x implementation in the Cavium SDK due to a failure to
check the first byte of the padding bytes. A man-in-the-middle
attacker can exploit this, by sending specially crafted requests to
the server, to induce requests that allow determining the plaintext
chunks of data. This vulnerability is a variant of the POODLE attack.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuu93339");
  # https://vivaldi.net/en-US/userblogs/entry/there-are-more-poodles-in-the-forest
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f38496c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in bug ID CSCuu93339, or contact
the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model != "5506-X" && model != "5508-X" && model != "5516-X")
  audit(AUDIT_HOST_NOT, 'a Cisco ASA 5506-X / 5508-X / 5516-X');

fix = NULL;
flag = 0;
override = 0;
cbi = "CSCuu93339";

# 9.3 <= 9.3(3.2)
if (
  ver =~ "^9\.3\([0-2](\.[0-9]+)?\)$" ||
  ver =~ "^9\.3\(3(\.[0-2])?\)$"
)
  fix = "Upgrade to 9.4(2) or later or refer to the vendor.";
# 9.4
else if (ver =~ "^9\.4\([01][^0-9]" && check_asa_release(version:ver, patched:"9.4(1.4)"))
  fix = "9.4(1.4) / 9.4(2)";
# 9.5
else if (ver =~ "^9\.5[^0-9]" && check_asa_release(version:ver, patched:"9.5(1)"))
  fix = "9.5(1)";

if (isnull(fix))
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA", ver);

if (get_kb_item("Host/local_checks_enabled"))
{
  # Check for the workaround
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_all_ssl", "show run all ssl");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^ssl server-version tlsv1", string:buf)) flag++;
    if (preg(multiline:TRUE, pattern:"^ssl client-version tlsv1-only", string:buf)) flag++;
  }
  else if (cisco_needs_enable(buf)) {flag = 1; override = 1;}
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Cisco bug ID      : ' + cbi +
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + fix +
      '\n';
    security_note(port:0, extra:report+cisco_caveat(override));
  }
  else security_note(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
