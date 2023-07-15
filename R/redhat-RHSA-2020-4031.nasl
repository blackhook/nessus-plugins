##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:4031. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141014);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/25");

  script_cve_id(
    "CVE-2020-11018",
    "CVE-2020-11019",
    "CVE-2020-11038",
    "CVE-2020-11039",
    "CVE-2020-11040",
    "CVE-2020-11041",
    "CVE-2020-11042",
    "CVE-2020-11043",
    "CVE-2020-11044",
    "CVE-2020-11045",
    "CVE-2020-11046",
    "CVE-2020-11047",
    "CVE-2020-11048",
    "CVE-2020-11049",
    "CVE-2020-11058",
    "CVE-2020-11085",
    "CVE-2020-11086",
    "CVE-2020-11087",
    "CVE-2020-11088",
    "CVE-2020-11089",
    "CVE-2020-11522",
    "CVE-2020-11525",
    "CVE-2020-11526",
    "CVE-2020-13396",
    "CVE-2020-13397"
  );
  script_xref(name:"RHSA", value:"2020:4031");

  script_name(english:"RHEL 7 : freerdp (RHSA-2020:4031)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:4031 advisory.

  - freerdp: Out of bound read in cliprdr_server_receive_capabilities (CVE-2020-11018)

  - freerdp: Out of bound read in update_recv could result in a crash (CVE-2020-11019)

  - freerdp: Integer overflow in VIDEO channel (CVE-2020-11038)

  - freerdp: Out of bound read/write in usb redirection channel (CVE-2020-11039)

  - freerdp: Out of bound access in clear_decompress_subcode_rlex (CVE-2020-11040)

  - freerdp: Unchecked read of array offset in rdpsnd_recv_wave2_pdu (CVE-2020-11041)

  - freerdp: out-of-bounds read in update_read_icon_info function (CVE-2020-11042)

  - freerdp: out of bound read in rfx_process_message_tileset (CVE-2020-11043)

  - freerdp: double free in update_read_cache_bitmap_v3_order function (CVE-2020-11044)

  - freerdp: out of bounds read in update_read_bitmap_data function (CVE-2020-11045)

  - freerdp: out of bounds seek in update_read_synchronize function could lead out of bounds read
    (CVE-2020-11046)

  - freerdp: out-of-bounds read in autodetect_recv_bandwidth_measure_results function (CVE-2020-11047)

  - freerdp: out-of-bounds read could result in aborting the session (CVE-2020-11048)

  - freerdp: out-of-bound read of client memory that is then passed on to the protocol parser (CVE-2020-11049)

  - freerdp: stream out-of-bounds seek in rdp_read_font_capability_set could lead to out-of-bounds read
    (CVE-2020-11058)

  - freerdp: out-of-bounds read in cliprdr_read_format_list function (CVE-2020-11085)

  - freerdp: out-of-bounds read in ntlm_read_ntlm_v2_client_challenge function (CVE-2020-11086)

  - freerdp: out-of-bounds read in ntlm_read_AuthenticateMessage (CVE-2020-11087)

  - freerdp: out-of-bounds read in ntlm_read_NegotiateMessage (CVE-2020-11088)

  - freerdp: out-of-bounds read in irp functions (CVE-2020-11089)

  - freerdp: out-of-bounds read in gdi.c (CVE-2020-11522)

  - freerdp: out-of-bounds read in bitmap.c (CVE-2020-11525)

  - freerdp: Stream pointer out of bounds in update_recv_secondary_order could lead out of bounds read later
    (CVE-2020-11526)

  - freerdp: Out-of-bounds read in ntlm_read_ChallengeMessage in winpr/libwinpr/sspi/NTLM/ntlm_message.c.
    (CVE-2020-13396)

  - freerdp: Out-of-bounds read in security_fips_decrypt in libfreerdp/core/security.c (CVE-2020-13397)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11018");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11019");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11038");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11039");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11040");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11041");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11042");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11043");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11044");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11045");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11046");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11047");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11048");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11049");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11058");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11085");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11086");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11087");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11088");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11089");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11522");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11525");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-11526");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-13396");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2020-13397");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:4031");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835391");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835403");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835762");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835766");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835772");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1835779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1836223");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1836239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1836247");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1841189");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1841196");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844161");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844166");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844171");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844177");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1844184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1848008");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1848012");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1848018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1848022");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1848029");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1848034");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/1848038");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11522");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-13396");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 125, 129, 190, 476, 672, 770, 787, 805);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freerdp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwinpr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwinpr-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/os',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/debug',
      'content/dist/rhel-alt/server/7/7Server/power9/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/debug',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/optional/source/SRPMS',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/os',
      'content/dist/rhel-alt/server/7/7Server/system-z-a/s390x/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/debug',
      'content/dist/rhel/client/7/7Client/x86_64/optional/os',
      'content/dist/rhel/client/7/7Client/x86_64/optional/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/oracle-java-rm/os',
      'content/dist/rhel/client/7/7Client/x86_64/os',
      'content/dist/rhel/client/7/7Client/x86_64/source/SRPMS',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/debug',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/os',
      'content/dist/rhel/client/7/7Client/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/optional/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/oracle-java-rm/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/source/SRPMS',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/debug',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/os',
      'content/dist/rhel/computenode/7/7ComputeNode/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/highavailability/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/resilientstorage/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap-hana/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/sap/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/supplementary/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/debug',
      'content/dist/rhel/power/7/7Server/ppc64/optional/os',
      'content/dist/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/debug',
      'content/dist/rhel/power/7/7Server/ppc64/sap/os',
      'content/dist/rhel/power/7/7Server/ppc64/sap/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/debug',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/os',
      'content/dist/rhel/power/7/7Server/ppc64/supplementary/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/debug',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/os',
      'content/dist/rhel/server/7/7Server/x86_64/highavailability/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/debug',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/os',
      'content/dist/rhel/server/7/7Server/x86_64/nfv/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/optional/debug',
      'content/dist/rhel/server/7/7Server/x86_64/optional/os',
      'content/dist/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/oracle-java-rm/os',
      'content/dist/rhel/server/7/7Server/x86_64/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/debug',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/os',
      'content/dist/rhel/server/7/7Server/x86_64/resilientstorage/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/rt/debug',
      'content/dist/rhel/server/7/7Server/x86_64/rt/os',
      'content/dist/rhel/server/7/7Server/x86_64/rt/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap-hana/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/sap/debug',
      'content/dist/rhel/server/7/7Server/x86_64/sap/os',
      'content/dist/rhel/server/7/7Server/x86_64/sap/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/debug',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/os',
      'content/dist/rhel/server/7/7Server/x86_64/supplementary/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/os',
      'content/dist/rhel/system-z/7/7Server/s390x/highavailability/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/os',
      'content/dist/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/os',
      'content/dist/rhel/system-z/7/7Server/s390x/resilientstorage/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/os',
      'content/dist/rhel/system-z/7/7Server/s390x/sap/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/source/SRPMS',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/debug',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/os',
      'content/dist/rhel/system-z/7/7Server/s390x/supplementary/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/optional/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/oracle-java-rm/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/source/SRPMS',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/debug',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/os',
      'content/dist/rhel/workstation/7/7Workstation/x86_64/supplementary/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/debug',
      'content/fastrack/rhel/client/7/x86_64/optional/os',
      'content/fastrack/rhel/client/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/client/7/x86_64/os',
      'content/fastrack/rhel/client/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/debug',
      'content/fastrack/rhel/computenode/7/x86_64/optional/os',
      'content/fastrack/rhel/computenode/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/computenode/7/x86_64/os',
      'content/fastrack/rhel/computenode/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/debug',
      'content/fastrack/rhel/power/7/ppc64/optional/os',
      'content/fastrack/rhel/power/7/ppc64/optional/source/SRPMS',
      'content/fastrack/rhel/power/7/ppc64/os',
      'content/fastrack/rhel/power/7/ppc64/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/debug',
      'content/fastrack/rhel/server/7/x86_64/highavailability/os',
      'content/fastrack/rhel/server/7/x86_64/highavailability/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/optional/debug',
      'content/fastrack/rhel/server/7/x86_64/optional/os',
      'content/fastrack/rhel/server/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/debug',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/os',
      'content/fastrack/rhel/server/7/x86_64/resilientstorage/source/SRPMS',
      'content/fastrack/rhel/server/7/x86_64/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/debug',
      'content/fastrack/rhel/system-z/7/s390x/optional/os',
      'content/fastrack/rhel/system-z/7/s390x/optional/source/SRPMS',
      'content/fastrack/rhel/system-z/7/s390x/os',
      'content/fastrack/rhel/system-z/7/s390x/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/debug',
      'content/fastrack/rhel/workstation/7/x86_64/optional/os',
      'content/fastrack/rhel/workstation/7/x86_64/optional/source/SRPMS',
      'content/fastrack/rhel/workstation/7/x86_64/os',
      'content/fastrack/rhel/workstation/7/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'freerdp-2.1.1-2.el7', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'freerdp-2.1.1-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'freerdp-2.1.1-2.el7', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'freerdp-2.1.1-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'freerdp-devel-2.1.1-2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'freerdp-libs-2.1.1-2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwinpr-2.1.1-2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libwinpr-devel-2.1.1-2.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (empty_or_null(applicable_repo_urls)) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get() + redhat_report_package_caveat();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp / freerdp-devel / freerdp-libs / libwinpr / libwinpr-devel');
}
