#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77196);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-0786", "CVE-2013-6412");

  script_name(english:"SuSE 11.3 Security Update : augeas (SAT Patch Number 9574)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Augeas has been updated to fix a symlink overwrite problem.
(CVE-2012-0786 / CVE-2013-6412)

Also a bug has been fixed where 'augtool -s set was failing'.
(bnc#876044)

Additionally parsing the multipath configuration has been fixed.
bnc#871323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=885003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0786.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6412.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9574.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:augeas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:augeas-lenses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libaugeas0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libaugeas0-0.9.0-3.15.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libaugeas0-0.9.0-3.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"augeas-0.9.0-3.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"augeas-lenses-0.9.0-3.15.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libaugeas0-0.9.0-3.15.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
