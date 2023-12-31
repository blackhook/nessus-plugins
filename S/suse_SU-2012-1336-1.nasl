#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2012:1336-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83561);
  script_version("2.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2011-2483", "CVE-2012-2655", "CVE-2012-3488", "CVE-2012-3489");
  script_bugtraq_id(49241, 53812, 55072, 55074);

  script_name(english:"SUSE SLED10 / SLES10 Security Update : PostgreSQL (SUSE-SU-2012:1336-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PostgreSQL was updated to the latest stable release 8.1.23, fixing
various bugs and security issues.

The following security issues have been fixed :

  - CVE-2012-3488: This update fixes arbitrary read and
    write of files via XSL functionality.

  - CVE-2012-2655: postgresql: denial of service (stack
    exhaustion) via specially crafted SQL.

  - CVE-2011-2483: crypt_blowfish was mishandling 8 bit
    characters.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=ee84db0d1f4471abd4ab51536636eb1e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6a8ab54"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3488.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3489.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/700876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/765069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/770193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/776523"
  );
  # https://www.suse.com/support/update/announcement/2012/suse-su-20121336-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cf9ff4f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected PostgreSQL packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED10|SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10 / SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"postgresql-devel-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"postgresql-libs-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"postgresql-libs-32bit-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"postgresql-devel-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"postgresql-libs-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"postgresql-libs-32bit-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"postgresql-libs-32bit-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"postgresql-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"postgresql-contrib-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"postgresql-devel-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"postgresql-docs-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"postgresql-libs-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"postgresql-pl-8.1.23-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"postgresql-server-8.1.23-0.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PostgreSQL");
}
