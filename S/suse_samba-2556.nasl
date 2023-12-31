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
  script_id(29575);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2007-0452");

  script_name(english:"SuSE 10 Security Update : samba (ZYPP Patch Number 2556)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A logic error in the deferred open code can lead to an infinite loop
in Samba's smbd daemon. (CVE-2007-0452)

In addition the following changes are included with these packages :

  - Move tdb utils to the client package.

  - The version string of binaries reported by the -V option
    now include the package version control system version
    number.

  - Fix time value reporting in libsmbclient; [#195285].

  - Store and restore NT hashes as string compatible values;
    [#185053].

  - Added winbindd null sid fix; [#185053].

  - Fix from Alison Winters of SGI to build even if
    make_vscan is 0.

  - Send correct workstation name to prevent
    NT_STATUS_INVALID_WORKSTATION beeing returned in
    samlogon; [#148645], [#161051]."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-0452.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 2556.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:0, reference:"samba-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLED10", sp:0, reference:"samba-client-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLED10", sp:0, reference:"samba-winbind-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"samba-32bit-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"samba-client-32bit-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLED10", sp:0, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"samba-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"samba-client-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLES10", sp:0, reference:"samba-winbind-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"samba-32bit-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"samba-client-32bit-3.0.22-13.27")) flag++;
if (rpm_check(release:"SLES10", sp:0, cpu:"x86_64", reference:"samba-winbind-32bit-3.0.22-13.27")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
