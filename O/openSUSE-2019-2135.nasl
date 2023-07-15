#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2135.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(128866);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2018-20174", "CVE-2018-20175", "CVE-2018-20176", "CVE-2018-20177", "CVE-2018-20178", "CVE-2018-20179", "CVE-2018-20180", "CVE-2018-20181", "CVE-2018-20182", "CVE-2018-8791", "CVE-2018-8792", "CVE-2018-8793", "CVE-2018-8794", "CVE-2018-8795", "CVE-2018-8796", "CVE-2018-8797", "CVE-2018-8798", "CVE-2018-8799", "CVE-2018-8800");

  script_name(english:"openSUSE Security Update : rdesktop (openSUSE-2019-2135)");
  script_summary(english:"Check for the openSUSE-2019-2135 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for rdesktop fixes the following issues :

rdesktop was updated to 1.8.6 :

  - Fix protocol code handling new licenses

rdesktop was updated to 1.8.5 :

  - Add bounds checking to protocol handling in order to fix
    many security problems when communicating with a
    malicious server.

rdesktop was updated to 1.8.4 (fix for boo#1121448) :

  - Add rdp_protocol_error function that is used in several
    fixes

  - Refactor of process_bitmap_updates

  - Fix possible integer overflow in s_check_rem() on 32bit
    arch

  - Fix memory corruption in process_bitmap_data -
    CVE-2018-8794

  - Fix remote code execution in process_bitmap_data -
    CVE-2018-8795

  - Fix remote code execution in process_plane -
    CVE-2018-8797

  - Fix Denial of Service in mcs_recv_connect_response -
    CVE-2018-20175

  - Fix Denial of Service in mcs_parse_domain_params -
    CVE-2018-20175

  - Fix Denial of Service in sec_parse_crypt_info -
    CVE-2018-20176

  - Fix Denial of Service in sec_recv - CVE-2018-20176

  - Fix minor information leak in rdpdr_process -
    CVE-2018-8791

  - Fix Denial of Service in cssp_read_tsrequest -
    CVE-2018-8792

  - Fix remote code execution in cssp_read_tsrequest -
    CVE-2018-8793

  - Fix Denial of Service in process_bitmap_data -
    CVE-2018-8796

  - Fix minor information leak in rdpsnd_process_ping -
    CVE-2018-8798

  - Fix Denial of Service in process_secondary_order -
    CVE-2018-8799

  - Fix remote code execution in in ui_clip_handle_data -
    CVE-2018-8800

  - Fix major information leak in ui_clip_handle_data -
    CVE-2018-20174

  - Fix memory corruption in rdp_in_unistr - CVE-2018-20177

  - Fix Denial of Service in process_demand_active -
    CVE-2018-20178

  - Fix remote code execution in lspci_process -
    CVE-2018-20179

  - Fix remote code execution in rdpsnddbg_process -
    CVE-2018-20180

  - Fix remote code execution in seamless_process -
    CVE-2018-20181

  - Fix remote code execution in seamless_process_line -
    CVE-2018-20182

  - Fix building against OpenSSL 1.1

  - remove obsolete patches

  - rdesktop-Fix-OpenSSL-1.1-compability-issues.patch

  - rdesktop-Fix-crash-in-rdssl_cert_to_rkey.patch

  - update changes file

  - add missing info about bugzilla 1121448

  - Added rdesktop-Fix-decryption.patch Patch from
    https://github.com/rdesktop/rdesktop/pull/334 to fix
    connections to VirtualBox.

  - update to 1.8.6

  - Fix protocol code handling new licenses

  - update to 1.8.5

  - Add bounds checking to protocol handling in order to fix
    many security problems when communicating with a
    malicious server.

  - Trim redundant wording from description.

  - Use %make_install.

  - update to 1.8.4 (fix for boo#1121448)

  - Add rdp_protocol_error function that is used in several
    fixes

  - Refactor of process_bitmap_updates

  - Fix possible integer overflow in s_check_rem() on 32bit
    arch

  - Fix memory corruption in process_bitmap_data -
    CVE-2018-8794

  - Fix remote code execution in process_bitmap_data -
    CVE-2018-8795

  - Fix remote code execution in process_plane -
    CVE-2018-8797

  - Fix Denial of Service in mcs_recv_connect_response -
    CVE-2018-20175

  - Fix Denial of Service in mcs_parse_domain_params -
    CVE-2018-20175

  - Fix Denial of Service in sec_parse_crypt_info -
    CVE-2018-20176

  - Fix Denial of Service in sec_recv - CVE-2018-20176

  - Fix minor information leak in rdpdr_process -
    CVE-2018-8791

  - Fix Denial of Service in cssp_read_tsrequest -
    CVE-2018-8792

  - Fix remote code execution in cssp_read_tsrequest -
    CVE-2018-8793

  - Fix Denial of Service in process_bitmap_data -
    CVE-2018-8796

  - Fix minor information leak in rdpsnd_process_ping -
    CVE-2018-8798

  - Fix Denial of Service in process_secondary_order -
    CVE-2018-8799

  - Fix remote code execution in in ui_clip_handle_data -
    CVE-2018-8800

  - Fix major information leak in ui_clip_handle_data -
    CVE-2018-20174

  - Fix memory corruption in rdp_in_unistr - CVE-2018-20177

  - Fix Denial of Service in process_demand_active -
    CVE-2018-20178

  - Fix remote code execution in lspci_process -
    CVE-2018-20179

  - Fix remote code execution in rdpsnddbg_process -
    CVE-2018-20180

  - Fix remote code execution in seamless_process -
    CVE-2018-20181

  - Fix remote code execution in seamless_process_line -
    CVE-2018-20182

  - Fix building against OpenSSL 1.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/rdesktop/rdesktop/pull/334"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rdesktop packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rdesktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rdesktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rdesktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"rdesktop-1.8.6-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rdesktop-debuginfo-1.8.6-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rdesktop-debugsource-1.8.6-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rdesktop / rdesktop-debuginfo / rdesktop-debugsource");
}
