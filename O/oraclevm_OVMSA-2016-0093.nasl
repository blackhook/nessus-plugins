#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0093.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92691);
  script_version("2.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-1960", "CVE-2013-1961", "CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244", "CVE-2014-8127", "CVE-2014-8129", "CVE-2014-8130", "CVE-2014-9330", "CVE-2014-9655", "CVE-2015-1547", "CVE-2015-7554", "CVE-2015-8665", "CVE-2015-8668", "CVE-2015-8683", "CVE-2015-8781", "CVE-2015-8784", "CVE-2016-3632", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-5320");
  script_bugtraq_id(59607, 59609, 61695, 61849, 62019, 62082, 71789, 72323, 72352, 72353, 73438, 73441);

  script_name(english:"OracleVM 3.3 / 3.4 : libtiff (OVMSA-2016-0093)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Update patch for (CVE-2014-8127)

  - Related: #1335099

  - Fix patches for (CVE-2016-3990, CVE-2016-5320)

  - Related: #1335099

  - Add patches for CVEs :

  - CVE-2016-3632 CVE-2016-3945 (CVE-2016-3990)

  - CVE-2016-3991 (CVE-2016-5320)

  - Related: #1335099

  - Update patch for (CVE-2014-8129)

  - Related: #1335099

  - Merge previously released fixes for CVEs :

  - CVE-2013-1960 CVE-2013-1961 (CVE-2013-4231)

  - CVE-2013-4232 CVE-2013-4243 (CVE-2013-4244)

  - Resolves: #1335099

  - Patch typos in (CVE-2014-8127)

  - Related: #1299919

  - Fix CVE-2014-8127 and CVE-2015-8668 patches

  - Related: #1299919

  - Fixed patches on preview CVEs

  - Related: #1299919

  - This resolves several CVEs

  - CVE-2014-8127, CVE-2014-8129, (CVE-2014-8130)

  - CVE-2014-9330, CVE-2014-9655, (CVE-2015-8781)

  - CVE-2015-8784, CVE-2015-1547, (CVE-2015-8683)

  - CVE-2015-8665, CVE-2015-7554, (CVE-2015-8668)

  - Resolves: #1299919"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-August/000508.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68c2f69e"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-August/000509.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?413e6c1c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libtiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.3", reference:"libtiff-3.9.4-18.el6_8")) flag++;

if (rpm_check(release:"OVS3.4", reference:"libtiff-3.9.4-18.el6_8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff");
}
