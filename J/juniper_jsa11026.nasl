#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139033);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id(
    "CVE-2019-0131",
    "CVE-2019-0165",
    "CVE-2019-0166",
    "CVE-2019-0168",
    "CVE-2019-0169",
    "CVE-2019-11086",
    "CVE-2019-11087",
    "CVE-2019-11088",
    "CVE-2019-11090",
    "CVE-2019-11097",
    "CVE-2019-11100",
    "CVE-2019-11101",
    "CVE-2019-11102",
    "CVE-2019-11103",
    "CVE-2019-11104",
    "CVE-2019-11105",
    "CVE-2019-11106",
    "CVE-2019-11107",
    "CVE-2019-11108",
    "CVE-2019-11109",
    "CVE-2019-11110",
    "CVE-2019-11131",
    "CVE-2019-11132",
    "CVE-2019-11147"
  );
  script_xref(name:"JSA", value:"JSA11026");

  script_name(english:"Juniper Junos NFX150 Multiple Vulnerabilities (JSA11026)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Junos OS device is affected by multiple vulnerabilities in the BIOS
firmware, including the following:

  - Logic issue in subsystem in Intel(R) AMT before versions 11.8.70, 11.11.70, 11.22.70 and 12.0.45 may allow
    an unauthenticated user to potentially enable escalation of privilege via network access. (CVE-2019-11131)

  - Heap overflow in subsystem in Intel(R) CSME before versions 11.8.70, 11.11.70, 11.22.70, 12.0.45; Intel(R)
    TXE before versions 3.1.70 and 4.0.20 may allow an unauthenticated user to potentially enable escalation
    of privileges, information disclosure or denial of service via adjacent access. (CVE-2019-0169)

  - Insufficient input validation in the subsystem for Intel(R) AMT before version 12.0.45 may allow an
    unauthenticated user to potentially enable escalation of privilege via network access. (CVE-2019-11107)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00241.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7899cffc");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11026");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11026");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11131");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if ('NFX150' >!< toupper(model))
  audit(AUDIT_HOST_NOT, 'an affected model');

if (ver !~ "^([0-9]|1[0-8])\." &&
    ver !~ "^19\.[0-3]" &&
    ver !~ "^19\.4($|R[01])" &&
    ver !~ "^20\.1($|R[01])"
   )
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fix = '19.4R2 / 20.1R2 or later';

report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report, xss:TRUE);
