#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1090.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(139018);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/24");

  script_cve_id("CVE-2020-11017", "CVE-2020-11018", "CVE-2020-11019", "CVE-2020-11038", "CVE-2020-11039", "CVE-2020-11040", "CVE-2020-11041", "CVE-2020-11043", "CVE-2020-11085", "CVE-2020-11086", "CVE-2020-11087", "CVE-2020-11088", "CVE-2020-11089", "CVE-2020-11095", "CVE-2020-11096", "CVE-2020-11097", "CVE-2020-11098", "CVE-2020-11099", "CVE-2020-11521", "CVE-2020-11522", "CVE-2020-11523", "CVE-2020-11524", "CVE-2020-11525", "CVE-2020-11526", "CVE-2020-13396", "CVE-2020-13397", "CVE-2020-13398", "CVE-2020-4030", "CVE-2020-4031", "CVE-2020-4032", "CVE-2020-4033");

  script_name(english:"openSUSE Security Update : freerdp (openSUSE-2020-1090)");
  script_summary(english:"Check for the openSUSE-2020-1090 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for freerdp fixes the following issues :

frerdp was updated to version 2.1.2 (bsc#1171441,bsc#1173247 and
jsc#ECO-2006) :

  - CVE-2020-11017: Fixed a double free which could have
    denied the server's service.

  - CVE-2020-11018: Fixed an out of bounds read which a
    malicious clients could have triggered.

  - CVE-2020-11019: Fixed an issue which could have led to
    denial of service if logger was set to 'WLOG_TRACE'.

  - CVE-2020-11038: Fixed a buffer overflow when /video
    redirection was used.

  - CVE-2020-11039: Fixed an issue which could have allowed
    arbitrary memory read and write when USB redirection was
    enabled.

  - CVE-2020-11040: Fixed an out of bounds data read in
    clear_decompress_subcode_rlex.

  - CVE-2020-11041: Fixed an issue with the configuration
    for sound backend which could have led to server's
    denial of service.

  - CVE-2020-11043: Fixed an out of bounds read in
    rfx_process_message_tileset.

  - CVE-2020-11085: Fixed an out of bounds read in
    cliprdr_read_format_list.

  - CVE-2020-11086: Fixed an out of bounds read in
    ntlm_read_ntlm_v2_client_challenge.

  - CVE-2020-11087: Fixed an out of bounds read in
    ntlm_read_AuthenticateMessage.

  - CVE-2020-11088: Fixed an out of bounds read in
    ntlm_read_NegotiateMessage.

  - CVE-2020-11089: Fixed an out of bounds read in irp
    function family.

  - CVE-2020-11095: Fixed a global out of bounds read in
    update_recv_primary_order.

  - CVE-2020-11096: Fixed a global out of bounds read in
    update_read_cache_bitmap_v3_order.

  - CVE-2020-11097: Fixed an out of bounds read in
    ntlm_av_pair_get.

  - CVE-2020-11098: Fixed an out of bounds read in
    glyph_cache_put.

  - CVE-2020-11099: Fixed an out of bounds Read in
    license_read_new_or_upgrade_license_packet.

  - CVE-2020-11521: Fixed an out of bounds write in planar.c
    (bsc#1171443).

  - CVE-2020-11522: Fixed an out of bounds read in gdi.c
    (bsc#1171444).

  - CVE-2020-11523: Fixed an integer overflow in region.c
    (bsc#1171445).

  - CVE-2020-11524: Fixed an out of bounds write in
    interleaved.c (bsc#1171446).

  - CVE-2020-11525: Fixed an out of bounds read in bitmap.c
    (bsc#1171447).

  - CVE-2020-11526: Fixed an out of bounds read in
    update_recv_secondary_order (bsc#1171674).

  - CVE-2020-13396: Fixed an Read in
    ntlm_read_ChallengeMessage.

  - CVE-2020-13397: Fixed an out of bounds read in
    security_fips_decrypt due to uninitialized value.

  - CVE-2020-13398: Fixed an out of bounds write in
    crypto_rsa_common.

  - CVE-2020-4030: Fixed an out of bounds read in
    `TrioParse`.

  - CVE-2020-4031: Fixed a use after free in
    gdi_SelectObject.

  - CVE-2020-4032: Fixed an integer casting in
    `update_recv_secondary_order`.

  - CVE-2020-4033: Fixed an out of bound read in
    RLEDECOMPRESS.

  - Fixed an issue where freerdp failed with -fno-common
    (bsc#1169748).

  - Fixed an issue where USB redirection with FreeRDP was
    not working (bsc#1169679).

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174200"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected freerdp packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13398");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-wayland");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freerdp-wayland-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreerdp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreerdp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuwac0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuwac0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwinpr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwinpr2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uwac0-0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:winpr2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.1", reference:"freerdp-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-debuginfo-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-debugsource-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-devel-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-proxy-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-proxy-debuginfo-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-server-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-server-debuginfo-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-wayland-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"freerdp-wayland-debuginfo-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreerdp2-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreerdp2-debuginfo-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libuwac0-0-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libuwac0-0-debuginfo-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwinpr2-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libwinpr2-debuginfo-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"uwac0-0-devel-2.1.2-lp151.5.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"winpr2-devel-2.1.2-lp151.5.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freerdp / freerdp-debuginfo / freerdp-debugsource / freerdp-devel / etc");
}
