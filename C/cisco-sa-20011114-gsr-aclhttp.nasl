#TRUSTED 872a9c11ebdf0af1aadf03c87234a1fb2ee62321e140f4b3bf948d9e51603c6ef066b4758cbcab7fb9335e0059a3cbf1223b12e822f1ed2238af50f57c343b3f508db3ef2a72dd9a4c496d21ab955f42e04a29f6bd238ee821ba68a8b9653b45b75f99dd324d7922cefd62493fadbee0d4d757ce9553a05e4de53ee3fc17bd1b93922f287e68f6a40a5944947ae72820f4bf467bcb8948bd87b5df7fcece2380fae078c04c1865c11bcc6f730cf54c0d55c912fe6143549c97d75441555e85f169f50d4f31992e5810bccdfac68211d3cf8f069d3abd521142f4128ba9cb845dbbad35825193770c0cf8a6f79c3d00bf3428a3fa1128a9a3bdda2ff62c8746bcffb26aca85d418d534bc874c8086789b1edb06545f2c725ab1f36accd29c952ac4ab6fa3bc320dec2d42fecd81606b2027670d7a11c5588506cf8014000ca44e3af17daf71d88fd2bc3c8ca88b8218bba1e15e2d8ce1b3e22c8b8a28ac284089c83bc2d080674f8bf7e28b953b559db0947283722082361351e10dd87438af00d18894e04b3828d030949a3f083fe6da3a407103803a5f5e2816af2ceee3796996ccedefd989b4148b2ca5320f1b4f424169194ac6550459c7a06925440c74e33757fa036e59388c6799ea01c9a2a3c50c6a81d162eb036fe0767a998c825f9cbb090c7f263da39e8622d848625cbc334afa3f3c3b73646d2482a04d96fa6863
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a00800b168f.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(48959);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id(
  "CVE-2001-0862",
  "CVE-2001-0863",
  "CVE-2001-0864",
  "CVE-2001-0865",
  "CVE-2001-0866",
  "CVE-2001-0867"
 );
 script_bugtraq_id(3535, 3536, 3537, 3538, 3539, 3540, 3542);
 script_name(english:"Multiple Vulnerabilities in Access Control List Implementation for Cisco 12000 Series Internet Router - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch");
 script_set_attribute(attribute:"description", value:
'Six vulnerabilities involving Access Control List (ACL) has been
discovered in multiple releases of Cisco IOS Software Release for
Cisco 12000 Series Internet Routers. Not all vulnerabilities are
present in all IOS releases and only line cards based on the Engine 2
are affected by them.
No other Cisco product is vulnerable.
The workarounds are described in the Workarounds section.
');
 # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20011114-gsr-acl
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a3f9163");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a00800b168f.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?6f6e900d");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20011114-gsr-acl.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/11/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_xref(name:"CISCO-BUG-ID", value:"CSCddm44976");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdm4476");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdm44976");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt69741");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdt96370");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu03323");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu35175");
 script_xref(name:"CISCO-BUG-ID", value:"CSCdu57417");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20011114-gsr-acl");
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

# Vulnerability CSCdm4476
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(10.1)S", "12.0(11)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdu57417
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(19)S", "12.0(19.3)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(18.6)ST1", "12.0(19.3)ST", "12.0(19)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdu03323
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16)S2", "12.0(17)S", "12.0(17.5)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(16.6)ST1", "12.0(17)ST", "12.0(17.5)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdu03323
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16)S2", "12.0(17)S", "12.0(17.5)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(16.6)ST1", "12.0(17)ST", "12.0(17.5)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdu35175
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(19.6)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(19.6)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdt96370
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16)S1", "12.0(17)S", "12.0(17.1)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(15.6)ST3", "12.0(16)ST", "12.0(17.1)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

# Vulnerability CSCdt69741
# Affected: 12.0S
if (check_release(version: version,
                  patched: make_list("12.0(16.6)S2", "12.0(17)S", "12.0(17.3)S"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}
# Affected: 12.0ST
if (check_release(version: version,
                  patched: make_list("12.0(17.3)ST", "12.0(18)ST"))) {
 report_extra = '\nUpdate to ' + patch_update + ' or later\n'; flag++;
}

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"L3\s+Engine:\s+2", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:report_extra + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

