#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:3229-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164940);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/27");

  script_cve_id(
    "CVE-2022-1720",
    "CVE-2022-1968",
    "CVE-2022-2124",
    "CVE-2022-2125",
    "CVE-2022-2126",
    "CVE-2022-2129",
    "CVE-2022-2175",
    "CVE-2022-2182",
    "CVE-2022-2183",
    "CVE-2022-2206",
    "CVE-2022-2207",
    "CVE-2022-2208",
    "CVE-2022-2210",
    "CVE-2022-2231",
    "CVE-2022-2257",
    "CVE-2022-2264",
    "CVE-2022-2284",
    "CVE-2022-2285",
    "CVE-2022-2286",
    "CVE-2022-2287",
    "CVE-2022-2304",
    "CVE-2022-2343",
    "CVE-2022-2344",
    "CVE-2022-2345",
    "CVE-2022-2522",
    "CVE-2022-2571",
    "CVE-2022-2580",
    "CVE-2022-2581",
    "CVE-2022-2598",
    "CVE-2022-2816",
    "CVE-2022-2817",
    "CVE-2022-2819",
    "CVE-2022-2845",
    "CVE-2022-2849",
    "CVE-2022-2862",
    "CVE-2022-2874",
    "CVE-2022-2889",
    "CVE-2022-2923",
    "CVE-2022-2946",
    "CVE-2022-3016"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:3229-1");
  script_xref(name:"IAVB", value:"2022-B-0049-S");
  script_xref(name:"IAVB", value:"2023-B-0016-S");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : vim (SUSE-SU-2022:3229-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLES15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2022:3229-1 advisory.

  - Buffer Over-read in function grab_file_name in GitHub repository vim/vim prior to 8.2.4956. This
    vulnerability is capable of crashing the software, memory modification, and possible remote execution.
    (CVE-2022-1720)

  - Use After Free in GitHub repository vim/vim prior to 8.2. (CVE-2022-1968)

  - Buffer Over-read in GitHub repository vim/vim prior to 8.2. (CVE-2022-2124, CVE-2022-2175)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 8.2. (CVE-2022-2125, CVE-2022-2182,
    CVE-2022-2207)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 8.2. (CVE-2022-2126, CVE-2022-2183,
    CVE-2022-2206)

  - Out-of-bounds Write in GitHub repository vim/vim prior to 8.2. (CVE-2022-2129, CVE-2022-2210)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2.5163. (CVE-2022-2208)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 8.2. (CVE-2022-2231)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0. (CVE-2022-2257, CVE-2022-2286,
    CVE-2022-2287)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2264, CVE-2022-2284)

  - Integer Overflow or Wraparound in GitHub repository vim/vim prior to 9.0. (CVE-2022-2285)

  - Stack-based Buffer Overflow in GitHub repository vim/vim prior to 9.0. (CVE-2022-2304)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0044. (CVE-2022-2343)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0045. (CVE-2022-2344)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0046. (CVE-2022-2345)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0061. (CVE-2022-2522)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0101. (CVE-2022-2571)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0102. (CVE-2022-2580)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.0104. (CVE-2022-2581)

  - Undefined Behavior for Input to API in GitHub repository vim/vim prior to 9.0.0100. (CVE-2022-2598)

  - Out-of-bounds Read in GitHub repository vim/vim prior to 9.0.0212. (CVE-2022-2816)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0213. (CVE-2022-2817)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0211. (CVE-2022-2819)

  - Buffer Over-read in GitHub repository vim/vim prior to 9.0.0218. (CVE-2022-2845)

  - Heap-based Buffer Overflow in GitHub repository vim/vim prior to 9.0.0220. (CVE-2022-2849)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0221. (CVE-2022-2862)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0224. (CVE-2022-2874)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0225. (CVE-2022-2889)

  - NULL Pointer Dereference in GitHub repository vim/vim prior to 9.0.0240. (CVE-2022-2923)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0246. (CVE-2022-2946)

  - Use After Free in GitHub repository vim/vim prior to 9.0.0286. (CVE-2022-3016)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200270");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200697");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200701");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200732");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200884");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200902");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1200904");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201132");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201133");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201134");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201135");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201151");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201153");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201154");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201155");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201249");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201356");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1201863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202046");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202049");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202862");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-September/012199.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?79087daf");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1720");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-1968");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2124");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2125");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2126");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2129");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2175");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2182");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2183");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2206");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2207");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2208");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2210");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2231");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2257");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2264");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2284");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2285");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2286");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2287");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2304");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2343");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2344");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2345");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2522");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2580");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2581");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2816");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2819");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2845");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2849");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2874");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2889");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2923");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2946");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-3016");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2345");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-3016");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gvim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim-data-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:vim-small");
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
if (os_ver == "SLED15" && (! preg(pattern:"^(3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP3/4", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(0|1|2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP0/1/2/3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.1', 'SLES_SAP-release-15.1', 'SLE_HPC-ESPOS-release-1']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_BCL-release-15.2', 'SLES_SAP-release-15.2', 'SLE_HPC-ESPOS-release-2']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15', 'SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-desktop-applications-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'vim-small-9.0.0313-150000.5.25.1', 'sp':'3', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'vim-small-9.0.0313-150000.5.25.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3', 'SLE_HPC-release-15.3', 'sle-module-basesystem-release-15.3', 'sled-release-15.3', 'sles-release-15.3']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-desktop-applications-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'vim-small-9.0.0313-150000.5.25.1', 'sp':'4', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'vim-small-9.0.0313-150000.5.25.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4', 'SLE_HPC-release-15.4', 'sle-module-basesystem-release-15.4', 'sled-release-15.4', 'sles-release-15.4']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-1']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'0', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'0', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15', 'sles-ltss-release-15']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-15', 'SLE_HPC-LTSS-release-15', 'sles-ltss-release-15']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-2']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'vim-small-9.0.0313-150000.5.25.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'vim-data-9.0.0313-150000.5.25.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'vim-data-common-9.0.0313-150000.5.25.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'vim-small-9.0.0313-150000.5.25.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'0', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'gvim-9.0.0313-150000.5.25.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'vim-9.0.0313-150000.5.25.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gvim / vim / vim-data / vim-data-common / vim-small');
}
