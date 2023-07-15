#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0039.
#

include("compat.inc");

if (description)
{
  script_id(140019);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2013-3495", "CVE-2014-3566", "CVE-2014-3672", "CVE-2014-5146", "CVE-2014-7188", "CVE-2014-8594", "CVE-2014-8595", "CVE-2014-8866", "CVE-2014-8867", "CVE-2014-9065", "CVE-2015-0361", "CVE-2015-2044", "CVE-2015-2045", "CVE-2015-2151", "CVE-2015-2152", "CVE-2015-2751", "CVE-2015-2752", "CVE-2015-3340", "CVE-2015-4163", "CVE-2015-4164", "CVE-2015-7812", "CVE-2015-7813", "CVE-2015-7814", "CVE-2015-7835", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-8550", "CVE-2016-10013", "CVE-2016-10024", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-3712", "CVE-2016-6258", "CVE-2016-7777", "CVE-2016-9603", "CVE-2017-10912", "CVE-2017-10913", "CVE-2017-10914", "CVE-2017-10915", "CVE-2017-10917", "CVE-2017-10918", "CVE-2017-10920", "CVE-2017-10921", "CVE-2017-10922", "CVE-2017-12135", "CVE-2017-12136", "CVE-2017-12137", "CVE-2017-14316", "CVE-2017-14317", "CVE-2017-14319", "CVE-2017-15289", "CVE-2017-15588", "CVE-2017-15589", "CVE-2017-15590", "CVE-2017-15592", "CVE-2017-15593", "CVE-2017-15594", "CVE-2017-15595", "CVE-2017-15597", "CVE-2017-17044", "CVE-2017-17045", "CVE-2017-17563", "CVE-2017-17564", "CVE-2017-17565", "CVE-2017-17566", "CVE-2017-18030", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754", "CVE-2017-7228", "CVE-2017-8903", "CVE-2017-8904", "CVE-2017-8905", "CVE-2018-10981", "CVE-2018-10982", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2018-12207", "CVE-2018-15468", "CVE-2018-19961", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-19967", "CVE-2018-3620", "CVE-2018-3639", "CVE-2018-3646", "CVE-2018-3665", "CVE-2018-7540", "CVE-2018-7541", "CVE-2018-8897", "CVE-2019-11091", "CVE-2019-11135", "CVE-2019-18424", "CVE-2019-19577", "CVE-2019-19579", "CVE-2019-19583", "CVE-2020-0543", "CVE-2020-14364", "CVE-2020-15565", "CVE-2020-15567");
  script_bugtraq_id(61854, 69198, 70198, 70574, 71149, 71151, 71331, 71332, 71544, 71882, 72954, 72955, 73015, 73068, 73443, 73448, 74248, 75141, 75149);
  script_xref(name:"CEA-ID", value:"CEA-2019-0324");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2020-0039) (Bunker Buster) (Foreshadow) (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout) (Meltdown) (POODLE) (Spectre)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates : please see Oracle VM Security Advisory
OVMSA-2020-0039 for details."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-August/000995.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4372e41a"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10921");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows POP/MOV SS Local Privilege Elevation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_exists(rpm:"xen-4.4.4-155", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-4.4.4-155.0.90.el6")) flag++;
if (rpm_exists(rpm:"xen-tools-4.4.4-155", release:"OVS3.4") && rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-155.0.90.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
