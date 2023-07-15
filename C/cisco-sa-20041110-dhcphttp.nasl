#TRUSTED 35e9d24965327e9bb34082c3192bf795519313e242a6a8a1694efbbb6a42a0e72fba4ec76c9385a5d474c65080a3a58f668617b95f7d960de39b1719f154199484ee5b543e14104f7631c842fafa7fe39a6e8a62d9f91dc9dcd187751006f9a031e99524678d04a920a117d6f8e7ffed367db6b8a4e6ffff78801e1b9abaa28b0303d22d82e52aa767343e14d9feee72a774ddacc43ddeaaac0f20474cf1072077bf4047572a1afd3cfd8922a15792355239bc0fd9b0c8452515aa05685f3ec3c824a3f3d3c44d9fdf69383f9a70af4e8154927d6786de8f90ff9177d55745dfd99013aa222e2ca2aa18b5d589c4c1660c2322ec6e6b51a1726ca3fadc0dd483688c15a06064606e210c4dc9a31de315d3cd3288c0ceddf6335c6b942914f5f36683eddfe4123c9ccc1961887ec710558f325eca39303daba7e58a1653593cac3b87309c3aa7852ab9a516782a6e8e73bc0091673b7264bc717c822802eebd4e82437730c97fce7df28a5a90d92181dce736ab8abdc43665baeacebbd8a6d8b4401d339ad1c73a48fb29e6271b13edbaa1b3deb54bb9baecf09f056449455aa86f22afe9fd4ade58aee9084da5dfd5e0e947e0f5a5ec8ce83b3b087192f2c2ca351402f3b452020f3c7c77b961b9186c05283a5e5c4bbb1960c115b69cf1e8b1307768f22449fb6468c3ee0c435a2530c92fbff8e1407b6b221fae0d6f8ae687
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00803448c7.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48978);
 script_version("1.14");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2004-1111");
 script_xref(name:"CERT", value:"630104");
 script_name(english:"Cisco IOS DHCP Blocked Interface Denial-of-Service - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'Cisco IOS devices running branches of Cisco IOS version 12.2S that
have Dynamic Host Configuration Protocol (DHCP) server or relay agent
enabled, even if not configured, are vulnerable to a denial of service
where the input queue becomes blocked when receiving specifically
crafted DHCP packets. Cisco is providing free fixed software to address
this issue. There are also workarounds to mitigate this vulnerability.
This issue was introduced by the fix included in CSCdx46180 and is
being tracked by Cisco Bug ID CSCee50294.'
 );
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20041110-dhcp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c793e4c");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00803448c7.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?e24ccf46");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20041110-dhcp.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/11/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCdx46180");
 script_xref(name:"CISCO-BUG-ID", value:"CSCee50294");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20041110-dhcp");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report_extra = "";
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

# Affected: 12.2(18)EW
if (check_release(version: version,
                  patched: make_list("12.2(18)EW2"),
                  oldest: "12.2(18)EW")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(20)EW
if (version =~ "^12\.2\(20\)EW[0-9]*$") {
 report_extra = '\nUpdate to 12.2(20)EWA or later\n'; flag++;
}
# Affected: 12.2(18)EWA
if (check_release(version: version,
                  patched: make_list("12.2(20)EWA"),
                  oldest: "12.2(18)EWA")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(18)S
if (check_release(version: version,
                  patched: make_list("12.2(18)S6"),
                  oldest: "12.2(18)S")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(18)SE
if (check_release(version: version,
                  patched: make_list("12.2(20)SE3"),
                  oldest: "12.2(18)SE")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(18)SV
if (check_release(version: version,
                  patched: make_list("12.2(24)SV"),
                  oldest: "12.2(18)SV")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(18)SW
if (check_release(version: version,
                  patched: make_list("12.2(25)SW"),
                  oldest: "12.2(18)SW")) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.2(14)SZ
if (version =~ "^12\.2\(14\)SZ[0-9]*$") {
 report_extra = '\nUpdate to 12.2(20)S4 or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (!preg(pattern:"no\s+service\s+dhcp", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_warning(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
