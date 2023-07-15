#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4606. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133109);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/02");

  script_cve_id("CVE-2019-13725", "CVE-2019-13726", "CVE-2019-13727", "CVE-2019-13728", "CVE-2019-13729", "CVE-2019-13730", "CVE-2019-13732", "CVE-2019-13734", "CVE-2019-13735", "CVE-2019-13736", "CVE-2019-13737", "CVE-2019-13738", "CVE-2019-13739", "CVE-2019-13740", "CVE-2019-13741", "CVE-2019-13742", "CVE-2019-13743", "CVE-2019-13744", "CVE-2019-13745", "CVE-2019-13746", "CVE-2019-13747", "CVE-2019-13748", "CVE-2019-13749", "CVE-2019-13750", "CVE-2019-13751", "CVE-2019-13752", "CVE-2019-13753", "CVE-2019-13754", "CVE-2019-13755", "CVE-2019-13756", "CVE-2019-13757", "CVE-2019-13758", "CVE-2019-13759", "CVE-2019-13761", "CVE-2019-13762", "CVE-2019-13763", "CVE-2019-13764", "CVE-2019-13767", "CVE-2020-6377", "CVE-2020-6378", "CVE-2020-6379", "CVE-2020-6380");
  script_xref(name:"DSA", value:"4606");

  script_name(english:"Debian DSA-4606-1 : chromium - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the chromium web
browser.

  - CVE-2019-13725
    Gengming Liu and Jianyu Chen discovered a use-after-free
    issue in the bluetooth implementation.

  - CVE-2019-13726
    Sergei Glazunov discovered a buffer overflow issue.

  - CVE-2019-13727
    @piochu discovered a policy enforcement error.

  - CVE-2019-13728
    Rong Jian and Guang Gong discovered an out-of-bounds
    write error in the v8 JavaScript library.

  - CVE-2019-13729
    Zhe Jin discovered a use-after-free issue.

  - CVE-2019-13730
    Soyeon Park and Wen Xu discovered the use of a wrong
    type in the v8 JavaScript library.

  - CVE-2019-13732
    Sergei Glazunov discovered a use-after-free issue in the
    WebAudio implementation.

  - CVE-2019-13734
    Wenxiang Qian discovered an out-of-bounds write issue in
    the sqlite library.

  - CVE-2019-13735
    Gengming Liu and Zhen Feng discovered an out-of-bounds
    write issue in the v8 JavaScript library.

  - CVE-2019-13736
    An integer overflow issue was discovered in the pdfium
    library.

  - CVE-2019-13737
    Mark Amery discovered a policy enforcement error.

  - CVE-2019-13738
    Johnathan Norman and Daniel Clark discovered a policy
    enforcement error.

  - CVE-2019-13739
    xisigr discovered a user interface error.

  - CVE-2019-13740
    Khalil Zhani discovered a user interface error.

  - CVE-2019-13741
    Michal Bentkowski discovered that user input could be
    incompletely validated.

  - CVE-2019-13742
    Khalil Zhani discovered a user interface error.

  - CVE-2019-13743
    Zhiyang Zeng discovered a user interface error.

  - CVE-2019-13744
    Prakash discovered a policy enforcement error.

  - CVE-2019-13745
    Luan Herrera discovered a policy enforcement error.

  - CVE-2019-13746
    David Erceg discovered a policy enforcement error.

  - CVE-2019-13747
    Ivan Popelyshev and Andre Bonatti discovered an
    uninitialized value.

  - CVE-2019-13748
    David Erceg discovered a policy enforcement error.

  - CVE-2019-13749
    Khalil Zhani discovered a user interface error.

  - CVE-2019-13750
    Wenxiang Qian discovered insufficient validation of data
    in the sqlite library.

  - CVE-2019-13751
    Wenxiang Qian discovered an uninitialized value in the
    sqlite library.

  - CVE-2019-13752
    Wenxiang Qian discovered an out-of-bounds read issue in
    the sqlite library.

  - CVE-2019-13753
    Wenxiang Qian discovered an out-of-bounds read issue in
    the sqlite library.

  - CVE-2019-13754
    Cody Crews discovered a policy enforcement error.

  - CVE-2019-13755
    Masato Kinugawa discovered a policy enforcement error.

  - CVE-2019-13756
    Khalil Zhani discovered a user interface error.

  - CVE-2019-13757
    Khalil Zhani discovered a user interface error.

  - CVE-2019-13758
    Khalil Zhani discovered a policy enforecement error.

  - CVE-2019-13759
    Wenxu Wu discovered a user interface error.

  - CVE-2019-13761
    Khalil Zhani discovered a user interface error.

  - CVE-2019-13762
    csanuragjain discovered a policy enforecement error.

  - CVE-2019-13763
    weiwangpp93 discovered a policy enforecement error.

  - CVE-2019-13764
    Soyeon Park and Wen Xu discovered the use of a wrong
    type in the v8 JavaScript library.

  - CVE-2019-13767
    Sergei Glazunov discovered a use-after-free issue.

  - CVE-2020-6377
    Zhe Jin discovered a use-after-free issue.

  - CVE-2020-6378
    Antti Levomaki and Christian Jalio discovered a
    use-after-free issue.

  - CVE-2020-6379
    Guang Gong discovered a use-after-free issue.

  - CVE-2020-6380
    Sergei Glazunov discovered an error verifying extension
    messages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-13767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2020/dsa-4606"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium packages.

For the oldstable distribution (stretch), security support for
chromium has been discontinued.

For the stable distribution (buster), these problems have been fixed
in version 79.0.3945.130-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"10.0", prefix:"chromium", reference:"79.0.3945.130-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-common", reference:"79.0.3945.130-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-driver", reference:"79.0.3945.130-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-l10n", reference:"79.0.3945.130-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-sandbox", reference:"79.0.3945.130-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-shell", reference:"79.0.3945.130-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
