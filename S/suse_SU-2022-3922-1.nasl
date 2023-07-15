#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3922-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(167241);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id("CVE-2021-22569", "CVE-2022-1941", "CVE-2022-3171");
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3922-1");
  script_xref(name:"IAVA", value:"2022-A-0164");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : protobuf (SUSE-SU-2022:3922-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3922-1 advisory.

  - An issue in protobuf-java allowed the interleaving of com.google.protobuf.UnknownFieldSet fields in such a
    way that would be processed out of order. A small malicious payload can occupy the parser for several
    minutes by creating large numbers of short-lived objects that cause frequent, repeated pauses. We
    recommend upgrading libraries beyond the vulnerable versions. (CVE-2021-22569)

  - A parsing vulnerability for the MessageSet type in the ProtocolBuffers versions prior to and including
    3.16.1, 3.17.3, 3.18.2, 3.19.4, 3.20.1 and 3.21.5 for protobuf-cpp, and versions prior to and including
    3.16.1, 3.17.3, 3.18.2, 3.19.4, 3.20.1 and 4.21.5 for protobuf-python can lead to out of memory failures.
    A specially crafted message with multiple key-value per elements creates parsing issues, and can lead to a
    Denial of Service against services receiving unsanitized input. We recommend upgrading to versions 3.18.3,
    3.19.5, 3.20.2, 3.21.6 for protobuf-cpp and 3.18.3, 3.19.5, 3.20.2, 4.21.6 for protobuf-python. Versions
    for 3.16 and 3.17 are no longer updated. (CVE-2022-1941)

  - A parsing issue with binary data in protobuf-java core and lite versions prior to 3.21.7, 3.20.3, 3.19.6
    and 3.16.3 can lead to a denial of service attack. Inputs containing multiple instances of non-repeated
    embedded messages with repeated or unknown fields causes objects to be converted back-n-forth between
    mutable and immutable forms, resulting in potentially long garbage collection pauses. We recommend
    updating to the versions mentioned above. (CVE-2022-3171)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203681");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1204256");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-November/012857.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4452e19");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22569");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3171");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22569");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3171");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprotobuf-lite20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprotobuf20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libprotoc20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:protobuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-protobuf");
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
if (os_ver == "SLED15" && (! preg(pattern:"^(2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP2/3/4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'2', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'sle-module-basesystem-release-15.2', 'sled-release-15.2', 'sles-release-15.2']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'sle-module-basesystem-release-15.2', 'sled-release-15.2', 'sles-release-15.2']},
    {'reference':'python3-protobuf-3.9.2-150200.4.19.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2', 'SLE_HPC-release-15.2', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-development-tools-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python2-protobuf-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python2-protobuf-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python3-protobuf-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'python3-protobuf-3.9.2-150200.4.19.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-packagehub-subpackages-release-15.3', 'sle-module-public-cloud-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-development-tools-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python2-protobuf-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python2-protobuf-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python3-protobuf-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'python3-protobuf-3.9.2-150200.4.19.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-packagehub-subpackages-release-15.4', 'sle-module-public-cloud-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libprotobuf-lite20-32bit-3.9.2-150200.4.19.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libprotobuf20-32bit-3.9.2-150200.4.19.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libprotoc20-32bit-3.9.2-150200.4.19.2', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'protobuf-java-3.9.2-150200.4.19.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'protobuf-source-3.9.2-150200.4.19.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'python2-protobuf-3.9.2-150200.4.19.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'python3-protobuf-3.9.2-150200.4.19.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libprotobuf-lite20-32bit-3.9.2-150200.4.19.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libprotobuf20-32bit-3.9.2-150200.4.19.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libprotoc20-32bit-3.9.2-150200.4.19.2', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'protobuf-java-3.9.2-150200.4.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'protobuf-source-3.9.2-150200.4.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python3-protobuf-3.9.2-150200.4.19.2', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'libprotobuf-lite20-3.9.2-150200.4.19.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'libprotobuf20-3.9.2-150200.4.19.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'libprotoc20-3.9.2-150200.4.19.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'protobuf-devel-3.9.2-150200.4.19.2', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libprotobuf-lite20 / libprotobuf-lite20-32bit / libprotobuf20 / etc');
}
