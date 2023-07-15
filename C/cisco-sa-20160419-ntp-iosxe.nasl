#TRUSTED 8896d02dc05630af03913247291208002adef245a5711d62ee5f499f7d5b976f1604094a575dc480f1195458aea522f7c82a0502802b44cbce9627b45fffe2c604c155fd8542ea37409a3c1f19c7dc32e555aa3fe2eabd56b142dab21470a825c05c7142122769baacaa7e4ae0ee9126fe4dc6a8bdb1e9784df9118224d0216dea43c02fb3bcf6a61ae8a7a7e82d7a8560f1019f78360326ac607c7b9a26a1ca5d6253ad5333d6b687e6a7dec4a1c3a679fce30cc352523dfd8858e19667e4d84fe0ef7ef83b3af671af76e6df356d13ec6bb2c7fad715f3ad87a42ec394849a73cb10d5386cb7a85818957073750e7a9a4f696bd7cd4bbe4398e65c3ab8d2aa7db53c26884a69b7a13a0669eb4447b09c41c3993ae64dd0640ea3146238f5bb75d6a2b3a73e43422c0e4524738eec8c7adb50f3efd4f0b0e60145b4ae0eb5bb4aa5b7bd56ec6c5bb90d57f33c7ca4a54f86b0471a0e35dfc40f5a15bef30dbc920e99c9043fca649204a8c92e00d87dc1f720776ffc66a43caaef3966b9ffca73034c1b78ea7852ced5ee0b52720ad1e94c7462f89d381eb2010a9d24f059f909143e52c47d34b9304dbeabfd6561a5a65cfc7e0677c30f6708eafd0234ebffd7f056d9c1058597419e05c90e32108b9f06759cdba6367d5b576f1a1a6c8664a07028397d730b1e5c6ce4bccff82971867bd738e11a52008ffc198259a43b8d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90862);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1384");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux46898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160419-ios");

  script_name(english:"Cisco IOS XE NTP Subsystem Unauthorized Access (cisco-sa-20160419-ios)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by an unauthorized access
vulnerability in the NTP subsystem due to a failure to check the
authorization of certain NTP packets. An unauthenticated, remote
attacker can exploit this issue, via specially crafted NTP packets, to
control the time of the remote device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160419-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8965288b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux46898.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

# Check for vuln version
if ( ver == '3.2.0JA' ) flag++;
if ( ver == '3.8.0E' ) flag++;
if ( ver == '3.8.1E' ) flag++;
if ( ver == '3.8.0EX' ) flag++;
if ( ver == '3.2.0S' ) flag++;
if ( ver == '3.2.1S' ) flag++;
if ( ver == '3.2.2S' ) flag++;
if ( ver == '3.2.3S' ) flag++;
if ( ver == '3.2.0SE' ) flag++;
if ( ver == '3.2.1SE' ) flag++;
if ( ver == '3.2.2SE' ) flag++;
if ( ver == '3.2.3SE' ) flag++;
if ( ver == '3.2.0SG' ) flag++;
if ( ver == '3.2.1SG' ) flag++;
if ( ver == '3.2.2SG' ) flag++;
if ( ver == '3.2.3SG' ) flag++;
if ( ver == '3.2.4SG' ) flag++;
if ( ver == '3.2.5SG' ) flag++;
if ( ver == '3.2.6SG' ) flag++;
if ( ver == '3.2.7SG' ) flag++;
if ( ver == '3.2.8SG' ) flag++;
if ( ver == '3.2.9SG' ) flag++;
if ( ver == '3.2.10SG' ) flag++;
if ( ver == '3.2.0XO' ) flag++;
if ( ver == '3.2.1XO' ) flag++;
if ( ver == '3.3.0S' ) flag++;
if ( ver == '3.3.1S' ) flag++;
if ( ver == '3.3.2S' ) flag++;
if ( ver == '3.3.0SE' ) flag++;
if ( ver == '3.3.1SE' ) flag++;
if ( ver == '3.3.2SE' ) flag++;
if ( ver == '3.3.3SE' ) flag++;
if ( ver == '3.3.4SE' ) flag++;
if ( ver == '3.3.5SE' ) flag++;
if ( ver == '3.3.0SG' ) flag++;
if ( ver == '3.3.1SG' ) flag++;
if ( ver == '3.3.2SG' ) flag++;
if ( ver == '3.3.0SQ' ) flag++;
if ( ver == '3.3.1SQ' ) flag++;
if ( ver == '3.3.0XO' ) flag++;
if ( ver == '3.3.1XO' ) flag++;
if ( ver == '3.3.2XO' ) flag++;
if ( ver == '3.4.0S' ) flag++;
if ( ver == '3.4.0aS' ) flag++;
if ( ver == '3.4.1S' ) flag++;
if ( ver == '3.4.2S' ) flag++;
if ( ver == '3.4.3S' ) flag++;
if ( ver == '3.4.4S' ) flag++;
if ( ver == '3.4.5S' ) flag++;
if ( ver == '3.4.6S' ) flag++;
if ( ver == '3.4.0SG' ) flag++;
if ( ver == '3.4.1SG' ) flag++;
if ( ver == '3.4.2SG' ) flag++;
if ( ver == '3.4.3SG' ) flag++;
if ( ver == '3.4.4SG' ) flag++;
if ( ver == '3.4.5SG' ) flag++;
if ( ver == '3.4.6SG' ) flag++;
if ( ver == '3.4.7SG' ) flag++;
if ( ver == '3.4.0SQ' ) flag++;
if ( ver == '3.4.1SQ' ) flag++;
if ( ver == '3.5.0E' ) flag++;
if ( ver == '3.5.1E' ) flag++;
if ( ver == '3.5.2E' ) flag++;
if ( ver == '3.5.3E' ) flag++;
if ( ver == '3.5.0S' ) flag++;
if ( ver == '3.5.1S' ) flag++;
if ( ver == '3.5.2S' ) flag++;
if ( ver == '3.5.1SQ' ) flag++;
if ( ver == '3.5.2SQ' ) flag++;
if ( ver == '3.5.0SQ' ) flag++;
if ( ver == '3.6.4E' ) flag++;
if ( ver == '3.6.0E' ) flag++;
if ( ver == '3.6.1E' ) flag++;
if ( ver == '3.6.2aE' ) flag++;
if ( ver == '3.6.2E' ) flag++;
if ( ver == '3.6.3E' ) flag++;
if ( ver == '3.6.0S' ) flag++;
if ( ver == '3.6.1S' ) flag++;
if ( ver == '3.6.2S' ) flag++;
if ( ver == '3.7.3E' ) flag++;
if ( ver == '3.7.0E' ) flag++;
if ( ver == '3.7.1E' ) flag++;
if ( ver == '3.7.2E' ) flag++;
if ( ver == '3.7.0S' ) flag++;
if ( ver == '3.7.0bS' ) flag++;
if ( ver == '3.7.0xaS' ) flag++;
if ( ver == '3.7.1S' ) flag++;
if ( ver == '3.7.1aS' ) flag++;
if ( ver == '3.7.2S' ) flag++;
if ( ver == '3.7.2tS' ) flag++;
if ( ver == '3.7.3S' ) flag++;
if ( ver == '3.7.4S' ) flag++;
if ( ver == '3.7.4aS' ) flag++;
if ( ver == '3.7.5S' ) flag++;
if ( ver == '3.7.6S' ) flag++;
if ( ver == '3.7.7S' ) flag++;
if ( ver == '3.8.0S' ) flag++;
if ( ver == '3.8.1S' ) flag++;
if ( ver == '3.8.2S' ) flag++;
if ( ver == '3.9.0S' ) flag++;
if ( ver == '3.9.0aS' ) flag++;
if ( ver == '3.9.1S' ) flag++;
if ( ver == '3.9.1aS' ) flag++;
if ( ver == '3.9.2S' ) flag++;
if ( ver == '3.10.0S' ) flag++;
if ( ver == '3.10.0aS' ) flag++;
if ( ver == '3.10.1S' ) flag++;
if ( ver == '3.10.1xbS' ) flag++;
if ( ver == '3.10.2S' ) flag++;
if ( ver == '3.10.2tS' ) flag++;
if ( ver == '3.10.3S' ) flag++;
if ( ver == '3.10.4S' ) flag++;
if ( ver == '3.10.5S' ) flag++;
if ( ver == '3.10.6S' ) flag++;
if ( ver == '3.10.7S' ) flag++;
if ( ver == '3.10.01S' ) flag++;
if ( ver == '3.11.0S' ) flag++;
if ( ver == '3.11.1S' ) flag++;
if ( ver == '3.11.2S' ) flag++;
if ( ver == '3.11.3S' ) flag++;
if ( ver == '3.11.4S' ) flag++;
if ( ver == '3.12.0S' ) flag++;
if ( ver == '3.12.0aS' ) flag++;
if ( ver == '3.12.1S' ) flag++;
if ( ver == '3.12.4S' ) flag++;
if ( ver == '3.12.2S' ) flag++;
if ( ver == '3.12.3S' ) flag++;
if ( ver == '3.13.2aS' ) flag++;
if ( ver == '3.13.5S' ) flag++;
if ( ver == '3.13.0S' ) flag++;
if ( ver == '3.13.0aS' ) flag++;
if ( ver == '3.13.1S' ) flag++;
if ( ver == '3.13.2S' ) flag++;
if ( ver == '3.13.3S' ) flag++;
if ( ver == '3.13.4S' ) flag++;
if ( ver == '3.14.0S' ) flag++;
if ( ver == '3.14.1S' ) flag++;
if ( ver == '3.14.2S' ) flag++;
if ( ver == '3.14.3S' ) flag++;
if ( ver == '3.14.4S' ) flag++;
if ( ver == '3.15.1cS' ) flag++;
if ( ver == '3.15.3S' ) flag++;
if ( ver == '3.15.0S' ) flag++;
if ( ver == '3.15.1S' ) flag++;
if ( ver == '3.15.2S' ) flag++;
if ( ver == '3.17.0S' ) flag++;
if ( ver == '3.17.1S' ) flag++;
if ( ver == '3.16.0S' ) flag++;
if ( ver == '3.16.0cS' ) flag++;
if ( ver == '3.16.1S' ) flag++;
if ( ver == '3.16.1aS' ) flag++;
if ( ver == '3.16.2S' ) flag++;
if ( ver == '3.16.2aS' ) flag++;

# NTP check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show ntp status");
  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
    if (
      "%NTP is not enabled." >< buf &&
      "system poll" >!< buf &&
      "Clock is" >!< buf
    ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled");
  }
  else if (cisco_needs_enable(buf)) override = 1;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux46898' +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_warning(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
