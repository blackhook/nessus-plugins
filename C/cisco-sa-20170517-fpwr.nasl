#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100426);
  script_version("1.7");
  script_cvs_date("Date: 2019/01/02 11:18:37");

  script_cve_id("CVE-2017-6632");
  script_bugtraq_id(98523);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd07072");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170517-fpwr");

  script_name(english:"Cisco Firepower System Software SSL Logging DoS (cisco-sa-20170517-fpwr)");
  script_summary(english:"Checks the version of Cisco Firepower System.");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Cisco Firepower Threat Defense (FTD)
software installed on the remote host is prior to 6.1.0.3 or else is
6.2.x prior to 6.2.1. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service vulnerability exists in the logging
    configuration of Secure Sockets Layer (SSL) policies. An
    unauthenticated, remote attacker can exploit this, via a
    flood of crafted TCP packets, to cause an excessive
    consumption of system resources. (CVE-2017-6632)

  - An unspecified information disclosure vulnerability
    exists that allows an unauthenticated, remote attacker
    to disclose potentially sensitive information. Note that
    this vulnerability only affects 6.1.0.2.

  - A denial of service vulnerability exists in the SSL
    detection engine that allows an unauthenticated, remote
    attacker to cause the Snort process to restart. Note
    that this vulnerability only affects 6.1.0.2.
");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170517-fpwr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?922f6cfb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd07072");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvd07072.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

# Affected Models:
# 5500-X Series
if (
   model !~ '^55[0-9][0-9][WH]?-X'
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product model");

fix = NULL;
override = 0;

fdm_ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (isnull(fdm_ver)) audit(AUDIT_HOST_NOT, "affected");

else if (fdm_ver[1] =~ "^6\.2\.")
  fix = '6.2.1';
else
  fix = '6.1.0.3';

# Cisco hasn't stated a fix, but lists the latest versions as vuln.
if (fix && (ver_compare(ver:fdm_ver[1], fix:fix, strict:FALSE) <= 0))
{
  report =
    '\n  Bug               : CSCvd07072' +
    '\n  Installed version : ' + fdm_ver[1] +
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
} else audit(AUDIT_HOST_NOT, "affected");
