#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4778. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(141843);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/13");

  script_cve_id("CVE-2020-15683", "CVE-2020-15969");
  script_xref(name:"DSA", value:"4778");
  script_xref(name:"IAVA", value:"2020-A-0472-S");

  script_name(english:"Debian DSA-4778-1 : firefox-esr - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues have been found in the Mozilla Firefox web
browser, which could potentially result in the execution of arbitrary
code."
  );
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/firefox-esr");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/firefox-esr");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4778");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the firefox-esr packages.

For the stable distribution (buster), these problems have been fixed
in version 78.4.0esr-1~deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15683");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"10.0", prefix:"firefox-esr", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ach", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-af", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-all", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-an", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ar", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-as", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ast", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-az", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-be", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-bg", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-bn-bd", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-bn-in", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-br", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-bs", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ca", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-cak", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-cs", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-cy", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-da", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-de", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-dsb", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-el", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-en-gb", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-en-za", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-eo", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-es-ar", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-es-cl", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-es-es", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-es-mx", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-et", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-eu", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-fa", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ff", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-fi", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-fr", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-fy-nl", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ga-ie", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-gd", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-gl", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-gn", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-gu-in", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-he", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-hi-in", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-hr", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-hsb", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-hu", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-hy-am", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ia", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-id", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-is", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-it", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ja", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ka", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-kab", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-kk", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-km", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-kn", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ko", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-lij", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-lt", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-lv", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-mai", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-mk", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ml", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-mr", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ms", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-my", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-nb-no", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ne-np", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-nl", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-nn-no", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-oc", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-or", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-pa-in", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-pl", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-pt-br", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-pt-pt", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-rm", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ro", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ru", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-si", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-sk", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-sl", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-son", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-sq", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-sr", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-sv-se", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ta", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-te", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-th", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-tr", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-uk", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-ur", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-uz", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-vi", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-xh", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-zh-cn", reference:"78.4.0esr-1~deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"firefox-esr-l10n-zh-tw", reference:"78.4.0esr-1~deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
