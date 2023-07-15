#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0033.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89817);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-5107");
  script_bugtraq_id(58162);

  script_name(english:"OracleVM 2.2 : openssh (OVMSA-2016-0033)");
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

  - change default value of MaxStartups - CVE-2010-5107
    (John Haxby)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-March/000422.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aec28cfa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openssh / openssh-clients / openssh-server
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/10");
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
if (! preg(pattern:"^OVS" + "2\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.2", reference:"openssh-4.3p2-82.0.1.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"openssh-clients-4.3p2-82.0.1.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"openssh-server-4.3p2-82.0.1.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-clients / openssh-server");
}
