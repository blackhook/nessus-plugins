#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0147.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102905);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-3702", "CVE-2010-3703", "CVE-2010-3704", "CVE-2017-9776");
  script_bugtraq_id(43594, 43841, 43845);

  script_name(english:"OracleVM 3.3 / 3.4 : poppler (OVMSA-2017-0147)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Resolves: rhbz#1479815 (CVE-2017-9776)

  - Don't crash on streams without Length

  - Resolves: #1302365

  - Use better default pixel size for printing of 0 width
    lines

  - Resolves: #1316163

  - Identification of fonts directly from streams and files

  - Resolves: #1208719

  - Embed type1 fonts to PostScript files correctly

  - Resolves: #1232210

  - Fix lines disappearing when selecting paragraph

  - Resolves: #614824

  - Silence illegal entry in bfrange block in ToUnicode CMap

  - Resolves: #710816

  - Fix captions of push button fields.

  - Resolves: #1191907

  - Add poppler-0.12.4-CVE-2010-3702.patch (Properly
    initialize parser)

  - Add poppler-0.12.4-CVE-2010-3703.patch (Properly
    initialize stack)

  - Add poppler-0.12.4-CVE-2010-3704.patch (Fix crash in
    broken pdf (code < 0))

  - Resolves: #639860"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-August/000779.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6e108d5"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-August/000776.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72469efb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler / poppler-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:poppler-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"poppler-0.12.4-12.el6_9")) flag++;
if (rpm_check(release:"OVS3.3", reference:"poppler-utils-0.12.4-12.el6_9")) flag++;

if (rpm_check(release:"OVS3.4", reference:"poppler-0.12.4-12.el6_9")) flag++;
if (rpm_check(release:"OVS3.4", reference:"poppler-utils-0.12.4-12.el6_9")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-utils");
}
