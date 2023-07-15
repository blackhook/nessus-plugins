##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0069. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147246);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id("CVE-2020-1751", "CVE-2020-1752");

  script_name(english:"NewStart CGSL MAIN 6.02 : glibc Multiple Vulnerabilities (NS-SA-2021-0069)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has glibc packages installed that are affected by multiple
vulnerabilities:

  - An out-of-bounds write vulnerability was found in glibc before 2.31 when handling signal trampolines on
    PowerPC. Specifically, the backtrace function did not properly check the array bounds when storing the
    frame address, resulting in a denial of service or potential code execution. The highest threat from this
    vulnerability is to system availability. (CVE-2020-1751)

  - A use-after-free vulnerability introduced in glibc upstream version 2.14 was found in the way the tilde
    expansion was carried out. Directory paths containing an initial tilde followed by a valid username were
    affected by this issue. A local attacker could exploit this flaw by creating a specially crafted path
    that, when processed by the glob function, would potentially lead to arbitrary code execution. This was
    fixed in version 2.32. (CVE-2020-1752)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0069");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL glibc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1751");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1752");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'compat-libpthread-nonshared-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-all-langpacks-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-benchtests-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-common-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-debuginfo-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-debuginfo-common-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-devel-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-headers-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-aa-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-af-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-agr-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ak-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-am-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-an-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-anp-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ar-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-as-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ast-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ayc-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-az-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-be-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-bem-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ber-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-bg-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-bhb-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-bho-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-bi-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-bn-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-bo-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-br-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-brx-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-bs-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-byn-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ca-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ce-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-chr-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-cmn-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-crh-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-cs-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-csb-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-cv-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-cy-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-da-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-de-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-doi-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-dsb-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-dv-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-dz-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-el-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-en-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-eo-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-es-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-et-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-eu-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-fa-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ff-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-fi-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-fil-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-fo-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-fr-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-fur-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-fy-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ga-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-gd-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-gez-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-gl-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-gu-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-gv-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ha-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-hak-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-he-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-hi-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-hif-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-hne-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-hr-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-hsb-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ht-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-hu-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-hy-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ia-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-id-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ig-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ik-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-is-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-it-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-iu-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ja-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ka-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-kab-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-kk-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-kl-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-km-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-kn-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ko-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-kok-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ks-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ku-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-kw-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ky-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-lb-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-lg-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-li-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-lij-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ln-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-lo-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-lt-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-lv-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-lzh-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mag-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mai-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mfe-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mg-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mhr-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mi-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-miq-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mjw-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mk-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ml-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mn-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mni-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mr-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ms-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-mt-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-my-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-nan-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-nb-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-nds-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ne-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-nhn-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-niu-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-nl-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-nn-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-nr-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-nso-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-oc-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-om-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-or-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-os-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-pa-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-pap-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-pl-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ps-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-pt-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-quz-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-raj-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ro-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ru-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-rw-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sa-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sah-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sat-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sc-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sd-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-se-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sgs-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-shn-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-shs-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-si-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sid-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sk-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sl-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sm-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-so-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sq-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sr-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ss-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-st-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sv-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-sw-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-szl-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ta-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-tcy-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-te-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-tg-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-th-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-the-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ti-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-tig-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-tk-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-tl-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-tn-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-to-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-tpi-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-tr-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ts-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-tt-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ug-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-uk-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-unm-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ur-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-uz-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-ve-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-vi-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-wa-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-wae-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-wal-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-wo-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-xh-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-yi-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-yo-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-yue-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-yuw-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-zh-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-langpack-zu-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-locale-source-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-minimal-langpack-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-nss-devel-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-static-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'glibc-utils-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'libnsl-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'nscd-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'nss_db-2.28-127.el8.cgslv6_2.0.2.g9e13e07b',
    'nss_hesiod-2.28-127.el8.cgslv6_2.0.2.g9e13e07b'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc');
}
