#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#

include('compat.inc');

if (description)
{
  script_id(168499);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/12");

  script_cve_id("CVE-2022-23093");
  script_xref(name:"IAVA", value:"2022-A-0508");

  script_name(english:"FreeBSD : FreeBSD -- ping stack buffer overflow (FreeBSD-SA-22:15.ping)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FreeBSD-SA-22:15.ping advisory.

  - ping contains a stack buffer overflow in the handling of incoming ICMP packets. A remote attacker can send
    specially crafted ICMP packets at an affected host causing the ping program to crash, or potentially,
    execute remote code as root.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.freebsd.org/security/advisories/FreeBSD-SA-22:15.ping.asc");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23093");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info", "Settings/ParanoidReport");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);

# FreeBSD core and FreeBSD kernel checks are always paranoid
# due to it being possible to manually patch without
# bumping the OS level
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var flag = 0;

var packages = [
    'FreeBSD>=12.3<12.3_10',
    'FreeBSD>=13.1<13.1_5'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
