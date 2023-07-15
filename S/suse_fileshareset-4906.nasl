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
  script_id(30037);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_name(english:"SuSE 10 Security Update : KDE (ZYPP Patch Number 4906)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update is necessary to support the new FlashPlayer version, which
required XEmbed support."
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4906.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/21");
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
if (rpm_check(release:"SLED10", sp:1, reference:"fileshareset-2.0-84.64")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-beagle-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-devel-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-kdm-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-ksysguardd-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-nsplugin-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-samba-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"kdebase3-session-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"kdebase3-32bit-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"fileshareset-2.0-84.64")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-devel-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-extra-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-kdm-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-ksysguardd-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-nsplugin-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-samba-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"kdebase3-session-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kdebase3-32bit-3.5.1-69.65")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"kdebase3-nsplugin64-3.5.1-69.65")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");