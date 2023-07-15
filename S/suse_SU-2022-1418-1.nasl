#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1418-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160283);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2021-36373", "CVE-2021-36374");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1418-1");
  script_xref(name:"IAVA", value:"2021-A-0480");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : ant (SUSE-SU-2022:1418-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:1418-1 advisory.

  - When reading a specially crafted TAR archive an Apache Ant build can be made to allocate large amounts of
    memory that finally leads to an out of memory error, even for small inputs. This can be used to disrupt
    builds using Apache Ant. Apache Ant prior to 1.9.16 and 1.10.11 were affected. (CVE-2021-36373)

  - When reading a specially crafted ZIP archive, or a derived formats, an Apache Ant build can be made to
    allocate large amounts of memory that leads to an out of memory error, even for small inputs. This can be
    used to disrupt builds using Apache Ant. Commonly used derived formats from ZIP archives are for instance
    JAR files and many office files. Apache Ant prior to 1.9.16 and 1.10.11 were affected. (CVE-2021-36374)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188468");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188469");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-April/010843.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6ddd07c0");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-36373");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-36374");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-antlr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-apache-bcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-apache-bsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-apache-log4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-apache-oro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-apache-regexp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-apache-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-commons-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-javamail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-jdepend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-jmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-junit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ant-swing");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15|SUSE15\.3|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ant-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-antlr-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-antlr-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-bcel-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-bcel-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-bsf-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-bsf-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-log4j-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-log4j-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-oro-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-oro-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-regexp-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-regexp-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-resolver-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-apache-resolver-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-commons-logging-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-commons-logging-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-javamail-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-javamail-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-jdepend-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-jdepend-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-jmf-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-jmf-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-junit-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-junit-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-manual-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-manual-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-scripts-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-scripts-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-swing-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-swing-1.10.7-150200.4.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'ant-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-antlr-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-apache-bcel-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-apache-bsf-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-apache-log4j-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-apache-oro-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-apache-regexp-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-apache-resolver-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-commons-logging-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-javamail-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-jdepend-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-jmf-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-junit-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-manual-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-scripts-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-swing-1.10.7-150200.4.6.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_RT-release-15.2']},
    {'reference':'ant-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-antlr-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-apache-bcel-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-apache-bsf-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-apache-log4j-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-apache-oro-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-apache-regexp-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-apache-resolver-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-apache-xalan2-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-commons-logging-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-commons-net-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-imageio-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-javamail-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-jdepend-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-jmf-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-jsch-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-junit-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-junit5-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-manual-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-scripts-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-swing-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-testutil-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-xz-1.10.7-150200.4.6.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'ant-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-antlr-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-apache-bcel-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-apache-bsf-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-apache-log4j-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-apache-oro-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-apache-regexp-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-apache-resolver-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-apache-xalan2-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-commons-logging-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-commons-net-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-imageio-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-javamail-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-jdepend-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-jmf-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-jsch-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-junit-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-junit5-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-manual-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-scripts-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-swing-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-testutil-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ant-xz-1.10.7-150200.4.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ant / ant-antlr / ant-apache-bcel / ant-apache-bsf / ant-apache-log4j / etc');
}
