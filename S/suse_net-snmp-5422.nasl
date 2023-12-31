#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(33787);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2008-0960", "CVE-2008-2292");

  script_name(english:"SuSE 10 Security Update : net-snmp (ZYPP Patch Number 5422)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This security update of net-snmp fixes a denial of service
vulnerability (CVE-2008-2292), an authentication bypass
(CVE-2008-0960) and several memory leaks.

In addition net-snmp was patched to allow customization of the agent
address set."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0960.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2292.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5422.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

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
if (rpm_check(release:"SLED10", sp:1, reference:"net-snmp-5.3.0.1-25.24.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"net-snmp-devel-5.3.0.1-25.24.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"perl-SNMP-5.3.0.1-25.24.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"net-snmp-32bit-5.3.0.1-25.24.3")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"net-snmp-5.3.0.1-25.26")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"net-snmp-devel-5.3.0.1-25.26")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"perl-SNMP-5.3.0.1-25.26")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"net-snmp-32bit-5.3.0.1-25.26")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"net-snmp-5.3.0.1-25.24.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"net-snmp-devel-5.3.0.1-25.24.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"perl-SNMP-5.3.0.1-25.24.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"net-snmp-32bit-5.3.0.1-25.24.3")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"net-snmp-5.3.0.1-25.26")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"net-snmp-devel-5.3.0.1-25.26")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"perl-SNMP-5.3.0.1-25.26")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"net-snmp-32bit-5.3.0.1-25.26")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
