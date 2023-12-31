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
  script_id(58408);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2010-3332");

  script_name(english:"SuSE 10 Security Update : Mono (ZYPP Patch Number 8001)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The FORMS authentication methods of mono ASP.net implementation were
vulnerable to a padding oracle attack as described in CVE-2010-3332,
as they did encryption after checksum.

This update changes the method to checksum after encryption to avoid
this attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3332.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8001.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, reference:"bytefx-data-mysql-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"ibm-data-db2-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-core-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-data-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-data-firebird-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-data-oracle-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-data-postgresql-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-data-sqlite-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-data-sybase-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-devel-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-extras-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-locale-extras-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-nunit-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-web-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"mono-winforms-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"mono-core-32bit-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-core-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-data-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-data-firebird-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-data-oracle-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-data-postgresql-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-data-sqlite-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-data-sybase-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-locale-extras-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-nunit-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-web-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"mono-winforms-1.2.2-12.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"mono-core-32bit-1.2.2-12.32.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
