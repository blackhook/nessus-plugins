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
  script_id(50960);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-2948", "CVE-2010-2949");

  script_name(english:"SuSE 11 / 11.1 Security Update : quagga (SAT Patch Numbers 3535 / 3536)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of quagga fixes two security issues :

  - Stack-based buffer overflow while processing malformed
    Route-Refresh messages. (CVE-2010-2948: CVSS v2 Base
    Score: 6.5 (MEDIUM) (AV:N/AC:L/Au:S/C:P/I:P/A:P))

  - Denial of service while processing malformed BGP update
    AS path messages. (CVE-2010-2949: CVSS v2 Base Score:
    5.0 (MEDIUM) (AV:N/AC:L/Au:N/C:N/I:N/A:P))"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=634300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2948.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2949.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 3535 / 3536 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:quagga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:0, reference:"quagga-0.99.10-17.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"quagga-0.99.15-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
