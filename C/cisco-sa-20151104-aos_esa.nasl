#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86914);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/28");

  script_cve_id("CVE-2015-4184", "CVE-2015-6291", "CVE-2015-6321");
  script_bugtraq_id(75181);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu35853");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu37733");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv47151");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus79774");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150612-esa");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151104-esa2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151104-aos");

  script_name(english:"Cisco Email Security Appliance Multiple Vulnerabilities");
  script_summary(english:"Checks the ESA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied security
patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco AsyncOS running on
the remote Cisco Email Security (ESA) appliance is affected by the
following vulnerabilities :

  - An anti-spam bypass vulnerability exists in the anti-spam
    scanner due to improper handling of malformed packets. An
    unauthenticated, remote attacker can exploit this, via
    a crafted DNS Sender Policy Framework (SPF) record, to
    bypass the scanner. (CVE-2015-4184)

  - A denial of service vulnerability exists in the email
    filtering feature due to improper input validation of
    email attachment fields. An unauthenticated, remote
    attacker can exploit this, via a crafted email with an
    attachment, to cause memory to be consumed at a high
    rate, resulting in the filtering process being restarted
    over again. (CVE-2015-6291)

  - A denial of service vulnerability exists due to improper
    handling of TCP packets sent at a high rate. An
    unauthenticated, remote attacker can exploit this to
    exhaust all available memory, preventing any more
    TCP connections from being accepted. (CVE-2015-6321)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150612-esa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fa713eb4");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-esa2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21ab6cfa");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-aos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?561dad7b");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant updates referenced in Cisco Security Advisories
cisco-sa-20150612-esa, cisco-sa-20151104-esa2, and
cisco-sa-20151104-aos.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4184");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/Version');

if (ver =~ "^[0-7]\.") # Prior to 8.0
  display_fix = '8.5.7-043';
else if (ver =~ "^8\.0\.2\.")
  display_fix = '9.1.1-023';
else if (ver =~ "^8\.0\.[01]\.") # 8.0 and 8.0.1
  display_fix = '8.5.7-043';
else if (ver =~ "^8\.5\.")
  display_fix = '8.5.7-043';
else if (ver =~ "^9\.0\.")
  display_fix = '9.1.1-023';
else if (ver =~ "^9\.1\.")
  display_fix = '9.1.1-023';
else if (ver =~ "^9\.5\.")
  display_fix = '9.6.0-046';
else if (ver =~ "^9\.6\.")
  display_fix = '9.6.0-046';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + display_fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);
