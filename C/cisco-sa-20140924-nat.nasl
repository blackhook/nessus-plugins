#TRUSTED 8a0468e84303eec2989855d22fb8b1c8d44843d0a3db5995e66156037cdb08468761a2022001a8b614f27218788efdd4bbdacfdb84fc8be56655ca51dcdb16ddd11b4dca7beee204f8af6ab2a4080475c55976570cf8a38df1def73de458d83e7cb0760e7be0742fa67b580fa79605c73482f008f8eedb3c10a4a69cba2d609a5be398d1cf303379a0262b37021604c0e645c839c659337668c58988a1c57991b3f2c9cb7b7552c1c2eb60bc4e7e8d5ab32e83a783b0a2891a43f34d72d789dd3aaea9d472bf8973bbf9ef01c637fd67970e804140db58717ea658de286aa28f9a718fcd75c9f3267829c47508cc14df47331e4d7ce33ada4619ae5f25952fa6f6c72b8ca600efe5ad2e8be77528ba27c7a3f2d622613f259405d183d72b203eb60cce08e33daf70824b81496c326793f4bcfc43fce971edd37c8cceee347120823b33d3a11dac69b7d346fbaf85ca8ddec892136e811dbf948ba0eebd39bb4eacf460a39af957d9aabde227451a0222b0c128bc6bf00690e20fe215606f910df480d7b4a490dd49ad9eec21f7f9e7d30e963e0ebb68a33b60ccc87ad039bf721253c1856937b549fcbacf87ea87a801d94ccd0807dbd6dd54bf68fecf3a760cb005e064adb131b8e7328d01857858802ecb9e2c962ce328876207ba8ac830e80c49e025ffd7ef0f11e4f4924c30b164a81132accec6281405f8737fbeae3bfb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77984);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3361");
  script_bugtraq_id(70129);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun54071");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-nat");

  script_name(english:"Cisco IOS Software Network Address Translation (NAT) ALG Module DoS (cisco-sa-20140924-nat)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in the Network Address Translation (NAT)
application-layer gateway (ALG) module. This issue exists due to
improper handling of multipart Session Description Protocol (SDP) in
Session Initiation Protocol (SIP) messages. A remote attacker can
exploit this issue by sending specially crafted SIP messages.

Note that the affected configuration is not enabled by default.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-nat
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b458c658");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35610");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCun54071");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-nat.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

app = "Cisco IOS";
cbi = "CSCun54071";
fixed_ver = NULL;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

#15.0M
if (ver == "15.0(1)M" || ver == "15.0(1)M1" || ver == "15.0(1)M10" || ver == "15.0(1)M2" || ver == "15.0(1)M3" || ver == "15.0(1)M4" || ver == "15.0(1)M5" || ver == "15.0(1)M6" || ver == "15.0(1)M6a" || ver == "15.0(1)M7" || ver == "15.0(1)M8" || ver == "15.0(1)M9")
  fixed_ver = "15.1(4)M9";
#15.0XA
else if (ver == "15.0(1)XA" || ver == "15.0(1)XA1" || ver == "15.0(1)XA2" || ver == "15.0(1)XA3" || ver == "15.0(1)XA4" || ver == "15.0(1)XA5")
  fixed_ver = "15.1(4)M9";
#15.1GC
else if (ver == "15.1(2)GC" || ver == "15.1(2)GC1" || ver == "15.1(2)GC2" || ver == "15.1(4)GC" || ver == "15.1(4)GC1")
  fixed_ver = "15.1(4)GC2";
#15.1M
else if (ver == "15.1(4)M" || ver == "15.1(4)M0a" || ver == "15.1(4)M0b" || ver == "15.1(4)M1" || ver == "15.1(4)M2" || ver == "15.1(4)M3" || ver == "15.1(4)M3a" || ver == "15.1(4)M4" || ver == "15.1(4)M5" || ver == "15.1(4)M6" || ver == "15.1(4)M7" || ver == "15.1(4)M8")
  fixed_ver = "15.1(4)M9";
#15.1T
else if (ver == "15.1(1)T" || ver == "15.1(1)T1" || ver == "15.1(1)T2" || ver == "15.1(1)T3" || ver == "15.1(1)T4" || ver == "15.1(1)T5" || ver == "15.1(2)T" || ver == "15.1(2)T0a" || ver == "15.1(2)T1" || ver == "15.1(2)T2" || ver == "15.1(2)T2a" || ver == "15.1(2)T3" || ver == "15.1(2)T4" || ver == "15.1(2)T5" || ver == "15.1(3)T" || ver == "15.1(3)T1" || ver == "15.1(3)T2" || ver == "15.1(3)T3" || ver == "15.1(3)T4")
  fixed_ver = "15.1(4)M9";
#15.1XB
else if (ver == "15.1(1)XB" || ver == "15.1(1)XB1" || ver == "15.1(1)XB2" || ver == "15.1(1)XB3" || ver == "15.1(4)XB4" || ver == "15.1(4)XB5" || ver == "15.1(4)XB5a" || ver == "15.1(4)XB6" || ver == "15.1(4)XB7" || ver == "15.1(4)XB8" || ver == "15.1(4)XB8a")
  fixed_ver = "15.1(4)M9";
#15.2GC
else if (ver == "15.2(1)GC" || ver == "15.2(1)GC1" || ver == "15.2(1)GC2" || ver == "15.2(2)GC" || ver == "15.2(3)GC" || ver == "15.2(3)GC1" || ver == "15.2(4)GC" || ver == "15.2(4)GC1" || ver == "15.2(4)GC2")
  fixed_ver = "15.2(4)M7";
#15.2GCA
else if (ver == "15.2(3)GCA" || ver == "15.2(3)GCA1")
  fixed_ver = "15.4(1)T2 or 15.4(2)T1";
#15.2JA
else if (ver == "15.2(2)JA" || ver == "15.2(2)JA1" || ver == "15.2(4)JA" || ver == "15.2(4)JA1")
  fixed_ver = "15.2(2)JA2 or 15.2(4)JA2";
#15.2JAX
else if (ver == "15.2(2)JAX" || ver == "15.2(2)JAX1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JAZ
else if (ver == "15.2(4)JAZ")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JB
else if (ver == "15.2(2)JB" || ver == "15.2(2)JB1" || ver == "15.2(2)JB2" || ver == "15.2(2)JB3" || ver == "15.2(4)JB" || ver == "15.2(4)JB1" || ver == "15.2(4)JB2" || ver == "15.2(4)JB3" || ver == "15.2(4)JB3a" || ver == "15.2(4)JB3b" || ver == "15.2(4)JB3h" || ver == "15.2(4)JB3s" || ver == "15.2(4)JB4" || ver == "15.2(4)JB5" || ver == "15.2(4)JB5h" || ver == "15.2(4)JB5m" || ver == "15.2(4)JB50")
  fixed_ver = "15.2(4)JB50a";
#15.2JN
else if (ver == "15.2(2)JN1" || ver == "15.2(2)JN2" || ver == "15.2(4)JN")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2M
else if (ver == "15.2(4)M" || ver == "15.2(4)M1" || ver == "15.2(4)M2" || ver == "15.2(4)M3" || ver == "15.2(4)M4" || ver == "15.2(4)M5" || ver == "15.2(4)M6" || ver == "15.2(4)M6b")
  fixed_ver = "15.2(4)M7";
#15.2T
else if (ver == "15.2(1)T" || ver == "15.2(1)T1" || ver == "15.2(1)T2" || ver == "15.2(1)T3" || ver == "15.2(1)T3a" || ver == "15.2(1)T4" || ver == "15.2(2)T" || ver == "15.2(2)T1" || ver == "15.2(2)T2" || ver == "15.2(2)T3" || ver == "15.2(2)T4" || ver == "15.2(3)T" || ver == "15.2(3)T1" || ver == "15.2(3)T2" || ver == "15.2(3)T3" || ver == "15.2(3)T4")
  fixed_ver = "15.2(4)M7";
#15.2XA
else if (ver == "15.2(3)XA")
  fixed_ver = "15.2(4)M7";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "15.2(4)XB11";
#15.3JA
else if (ver == "15.3(3)JA75")
  fixed_ver = "Refer to the vendor for a fix.";
#15.3M
else if (ver == "15.3(3)M" || ver == "15.3(3)M1" || ver == "15.3(3)M2")
  fixed_ver = "15.3(3)M3";
#15.3T
else if (ver == "15.3(1)T" || ver == "15.3(1)T1" || ver == "15.3(1)T2" || ver == "15.3(1)T3" || ver == "15.3(1)T4" || ver == "15.3(2)T" || ver == "15.3(2)T1" || ver == "15.3(2)T2" || ver == "15.3(2)T3")
  fixed_ver = "15.3(2)T4";
#15.4CG
else if (ver == "15.4(1)CG" || ver == "15.4(1)CG1" || ver == "15.4(2)CG")
  fixed_ver = "Refer to the vendor for a fix.";
#15.4T
else if (ver == "15.4(1)T" || ver == "15.4(1)T1" || ver == "15.4(2)T")
  fixed_ver = "15.4(1)T2 or 15.4(2)T1";

if (isnull(fixed_ver))
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

# NAT check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_nat_statistics", "show ip nat statistics");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:"^Outside interfaces:\s+.*\s+Inside interfaces:", string:buf) ||
      preg(multiline:TRUE, pattern:"^Inside interfaces:\s+.*\s+Hits:", string:buf)
    ) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # NAT may still be active on the device through the NAT Virtual Interface feature
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_nat_nvi_statistics", "show ip nat nvi statistics");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^NAT Enabled interfaces:\s+.*\s+Hits:", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because NAT is not active.");
}


if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
