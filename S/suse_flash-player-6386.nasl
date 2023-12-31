#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51731);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/08");

  script_cve_id(
    "CVE-2009-0901",
    "CVE-2009-1862",
    "CVE-2009-1863",
    "CVE-2009-1864",
    "CVE-2009-1865",
    "CVE-2009-1866",
    "CVE-2009-1867",
    "CVE-2009-1868",
    "CVE-2009-1869",
    "CVE-2009-1870",
    "CVE-2009-2395",
    "CVE-2009-2493"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"SuSE 10 Security Update : flash-player (ZYPP Patch Number 6386)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 10 host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"Specially crafted Flash (SWF) files can cause a buffer overflow in
flash-player. Attackers could potentially exploit that to execute
arbitrary code. (CVE-2009-1862 / CVE-2009-0901 / CVE-2009-2395 /
CVE-2009-2493 / CVE-2009-1863 / CVE-2009-1864 / CVE-2009-1865 /
CVE-2009-1866 / CVE-2009-1867 / CVE-2009-1868 / CVE-2009-1869 /
CVE-2009-1870)");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-0901.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-1862.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-1863.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-1864.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-1865.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-1866.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-1867.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-1868.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-1869.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-1870.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-2395.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2009-2493.html");
  script_set_attribute(attribute:"solution", value:
"Apply ZYPP patch number 6386.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(59, 89, 94, 119, 189, 200, 264);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2022 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:2, reference:"flash-player-9.0.246.0-0.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
