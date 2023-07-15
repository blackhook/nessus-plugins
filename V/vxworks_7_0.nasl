#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152701);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/23");

  script_cve_id("CVE-2020-13603", "CVE-2020-35198");
  script_xref(name:"IAVA", value:"2021-A-0387");

  script_name(english:"Wind River VxWorks < 7.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote VxWorks device is potentially affected by multiple remote
code execution and denial-of-service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote device is Wind River VxWorks and it's affected by multiple
vulnerabilities:

 - The memory allocator has a possible integer overflow in calculating a memory block's size to be allocated by
   calloc(). As a result, the actual memory allocated is smaller than the buffer size specified by the arguments,
   leading to memory corruption. (CVE-2020-35198)

 - memory allocator has a possible overflow in calculating the memory block's size to be allocated by calloc().
   As a result, the actual memory allocated is smaller than the buffer size specified by the arguments, leading
   to memory corruption. (CVE-2020-13603)

Note that Nessus has not tested for this issue but has instead relied only on the OS version.");
  script_set_attribute(attribute:"see_also", value:"https://us-cert.cisa.gov/ics/advisories/icsa-21-119-04");
  script_set_attribute(attribute:"solution", value:
"Contact the device vendor to obtain the appropriate update");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-28895");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:windriver:vxworks");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("windriver_vxworks_rtos_detect.nbin");
  script_require_keys("Host/VxWorks");

  exit(0);
}

get_kb_item_or_exit('Host/VxWorks');
var version = get_kb_item('Host/VxWorks/version');
if (empty_or_null(version))
  version = 'unknown';

var vuln = FALSE;

if (version != 'unknown')
{
  if (ver_compare(ver:version, fix:"7.0", strict:FALSE) < 0)
  {
    vuln = TRUE;
  }
}
else if (report_paranoia >= 2)
{
  # if we cannot tell the version but the check is paranoid, report
  vuln = TRUE;
}

if (vuln)
{
  report =
    '\n    Version       : ' + version +
    '\n    Fixed Version : Check Vendor Adversary' +
    '\n';

  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else if (version == 'unknown') audit(AUDIT_POTENTIAL_VULN, 'VxWorks');
else audit(AUDIT_OS_RELEASE_NOT, 'VxWorks', version);
