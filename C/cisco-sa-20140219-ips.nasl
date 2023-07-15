#TRUSTED a3c9cb58fe32952fe5f165fe9192a42e8017557659559b0d77dd7c35bc46e15cd3c362ca6cb6fea0518ddb247a956c9fa25585755a1360eee3dd06bf6782fb9c8e50b7f351fb8ca0a85ef7b336ef37e7fd1ebd2d32ad7d5f10c4a93b16fa3c302b1719bc1acbb8bb1c229856c23cccc39545c230897df8ec376ce47ed3f0075310800b1d36fda4f7b0a8ba88dfbca54e9cc1eede525ebf3e83da29e3616368f6ab076630f979d770cc5014d119d17f86fa151ccf9348c96f41219c6f9a9436ab223b5379b98418c71dbf3dd06aec5f077d54ab85954a00c0ea495343b304eec184072148833993de17565d4e8a97eba30d28bce602b52e71543ee2508f1863898a1fa447d5eabc5aba275005038fcf031d7ea418d5a641515c5f74dee10eb7272f1264abef8241663587dbe3b9c59aa5bbdc988b0882d4a4248bf228753505b5e40bb96647a94fe4ced6aede1b960024f93aa6980619f6cab2ec76ba6958a3b689135d777e575ba2dd0de53c26953ac0c5b8a802ebcc98e977c8706becd2c635451fbeb83275a791f8509ff37519097df00baf4b280edc5a34fae238a72974e6415d364e736f8b456c3020a42cef790bad83c18d9d0a71e09d6f16a21d440baaaee33fa0fefb10ef8f81343cebc34e056eb5b67f403ea46b7b9d51b6ac6067d8d3a54eb65469b63601e59df90e03993e229e39e500dd99d368f9078d915dcff0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72705);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-0718", "CVE-2014-0719", "CVE-2014-0720");
  script_bugtraq_id(65665, 65667, 65669);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui67394");
  script_xref(name:"IAVA", value:"2014-A-0032");
  script_xref(name:"CISCO-BUG-ID", value:"CSCui91266");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuh94944");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140219-ips");

  script_name(english:"Multiple Vulnerabilities in Cisco Intrusion Prevention System Software (cisco-sa-20140219-ips)");
  script_summary(english:"Checks the IPS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of the Cisco
Intrusion Prevention System software running on the remote is affected
by the following denial of service vulnerabilities :

  - The Analysis Engine can become unresponsive due to
    improper handling of fragmented packets processed
    through the device. The device is only affected when
    the 'produce-verbose-alert' action is enabled.
    (CVE-2014-0718)

  - The MainApp can become unresponsive due to improper
    handling of malformed TCP packets sent to the
    management interface. Other critical tasks such as
    alert notification, event store management, sensor
    authentication, and the Analysis Engine can become
    unresponsive as well. (CVE-2014-0719)

  - The Analysis Engine can become unresponsive due to
    improper handling of jumbo frames sent at a high rate.
    (CVE-2014-0720)

An unauthenticated, remote attacker can exploit these issues to cause
a denial of service."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140219-ips
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a789b5da");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20140219-ips."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:intrusion_prevention_system");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("cisco_ips_version.nasl");
  script_require_keys("Host/Cisco/IPS/Version", "Host/Cisco/IPS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Cisco/IPS/Version');
model = get_kb_item_or_exit('Host/Cisco/IPS/Model');
model_ver = eregmatch(pattern:"[^0-9]([0-9]{4,})[^0-9]", string:model);
model_ver = model_ver[1];

flag = 0;
report = '\n  Model: ' + model + '\n';
fixed_ver = "";

# #################################################
# CSCui91266
# #################################################
cbi = "CSCui91266";
temp_flag = 0;

if (
  model_ver =~ "^42\d\d$" || model_ver =~ "^43\d\d$" ||
  model_ver =~ "^45\d\d$" || model =~ "ASA.*SS(M|P)"
)
{
  if (ver =~ "^7\.1\([4-7](p\d)?\)E4")
  {
    temp_flag++;
    fixed_ver = "7.1(8)E4";

    # Check if the 'produce-verbose-alert' option is enabled
    if (get_kb_item("Host/local_checks_enabled"))
    {
      temp_flag = 0;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_configuration", "show configuration");
      if (check_cisco_result(buf))
        if (preg(multiline:TRUE, pattern:"produce-verbose-alert", string:buf)) temp_flag++;
    }
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCui67394
# #################################################
cbi = "CSCui67394";
temp_flag = 0;

if (model =~ "ASA.*SS(M|P)")
{
  if (
    ver =~ "^6\." ||
    ver =~ "^7\.0\(" ||
    ver =~ "^7\.1\([1-7](p\d)?\)E4" ||
    ver =~ "^7\.1\(8(p1)?\)E4")
  {
    temp_flag++;
    fixed_ver = "7.1(8p2)E4";
  }

  else if (ver =~ "^7\.2\(1(p[12])?\)E4")
  {
    temp_flag++;
    fixed_ver = "7.2(2)E4";
  }
}
# Cisco ASA 5505 Advanced Inspection and Prevention Security Services Card (AIP SSC)
else if (model =~ "ASA.*SSC")
{
  fixed_ver = "Refer to the Cisco advisory for more information.";
  temp_flag++;
}


if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# #################################################
# CSCuh94944
# #################################################
cbi = "CSCuh94944";
temp_flag = 0;

if (model_ver =~ "^45\d\d$")
{
  if (ver =~ "^7\.1\([1-7](p\d)?\)E4")
  {
    temp_flag++;
    fixed_ver = "7.1(8)E4";
  }
}

if (temp_flag)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver + '\n';
  flag++;
}

# Reporting
if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IPS', ver + ' on model ' + model);
