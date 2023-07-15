#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2020:14579-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150549);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/10");

  script_cve_id("CVE-2019-19906");
  script_xref(name:"SuSE", value:"SUSE-SU-2020:14579-1");

  script_name(english:"SUSE SLES11 Security Update : cyrus-sasl (SUSE-SU-2020:14579-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has packages installed that are affected by a vulnerability as referenced in the SUSE-
SU-2020:14579-1 advisory.

  - cyrus-sasl (aka Cyrus SASL) 2.1.27 has an out-of-bounds write leading to unauthenticated remote denial-of-
    service in OpenLDAP via a malformed LDAP packet. The OpenLDAP crash is ultimately caused by an off-by-one
    error in _sasl_add_string in common.c in cyrus-sasl. (CVE-2019-19906)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1159635");
  # https://lists.suse.com/pipermail/sle-security-updates/2020-December/008085.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab44e999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19906");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-crammd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-crammd5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-digestmd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-digestmd5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-gssapi-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-crammd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-crammd5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-crammd5-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-digestmd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-digestmd5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-digestmd5-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-gssapi-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-gssapi-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-ntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-otp-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-otp-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-plain-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-plain-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-openssl1-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-otp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-otp-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-plain-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-saslauthd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-sqlauxprop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-sasl-sqlauxprop-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(0|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP0/4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'cyrus-sasl-openssl1-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-crammd5-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-crammd5-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-crammd5-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-digestmd5-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-digestmd5-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-digestmd5-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-gssapi-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-gssapi-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-gssapi-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-ntlm-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-otp-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-otp-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-otp-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-plain-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-plain-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-plain-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.3-0'},
    {'reference':'cyrus-sasl-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-crammd5-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-crammd5-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-crammd5-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-digestmd5-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-digestmd5-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-digestmd5-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-gssapi-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-gssapi-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-gssapi-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-otp-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-otp-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-otp-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-plain-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-plain-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-plain-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-saslauthd-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-sqlauxprop-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-sqlauxprop-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-sqlauxprop-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'cyrus-sasl-openssl1-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-crammd5-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-crammd5-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-crammd5-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-digestmd5-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-digestmd5-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-digestmd5-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-gssapi-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-gssapi-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-gssapi-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-ntlm-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-otp-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-otp-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-otp-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-plain-2.1.22-182.26.4', 'sp':'0', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-plain-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-openssl1-plain-32bit-2.1.22-182.26.4', 'sp':'0', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.3-0'},
    {'reference':'cyrus-sasl-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-crammd5-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-crammd5-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-crammd5-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-digestmd5-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-digestmd5-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-digestmd5-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-gssapi-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-gssapi-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-gssapi-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-otp-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-otp-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-otp-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-plain-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-plain-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-plain-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-saslauthd-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-sqlauxprop-2.1.22-182.26.4', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-sqlauxprop-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'s390x', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'},
    {'reference':'cyrus-sasl-sqlauxprop-32bit-2.1.22-182.26.4', 'sp':'4', 'cpu':'x86_64', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cyrus-sasl / cyrus-sasl-32bit / cyrus-sasl-crammd5 / etc');
}
