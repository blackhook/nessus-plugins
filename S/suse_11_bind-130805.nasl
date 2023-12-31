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
  script_id(69259);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-4854");

  script_name(english:"SuSE 11.2 / 11.3 Security Update : bind (SAT Patch Numbers 8160 / 8161)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A specially crafted query with malicious rdata could have caused a
crash (DoS) in named."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4854.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8160 / 8161 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 Tenable Network Security, Inc.");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"bind-libs-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"bind-utils-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"bind-libs-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"bind-libs-32bit-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"bind-utils-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"bind-libs-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"bind-utils-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"bind-libs-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"bind-libs-32bit-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"bind-utils-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"bind-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"bind-chrootenv-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"bind-doc-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"bind-libs-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"bind-utils-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"bind-libs-32bit-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"bind-libs-32bit-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"bind-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"bind-chrootenv-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"bind-doc-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"bind-libs-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"bind-utils-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"bind-libs-32bit-9.9.3P2-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"bind-libs-32bit-9.9.3P2-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
