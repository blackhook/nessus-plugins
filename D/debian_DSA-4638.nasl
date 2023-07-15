#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4638. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(134433);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2019-19880", "CVE-2019-19923", "CVE-2019-19925", "CVE-2019-19926", "CVE-2020-6381", "CVE-2020-6382", "CVE-2020-6383", "CVE-2020-6384", "CVE-2020-6385", "CVE-2020-6386", "CVE-2020-6387", "CVE-2020-6388", "CVE-2020-6389", "CVE-2020-6390", "CVE-2020-6391", "CVE-2020-6392", "CVE-2020-6393", "CVE-2020-6394", "CVE-2020-6395", "CVE-2020-6396", "CVE-2020-6397", "CVE-2020-6398", "CVE-2020-6399", "CVE-2020-6400", "CVE-2020-6401", "CVE-2020-6402", "CVE-2020-6403", "CVE-2020-6404", "CVE-2020-6405", "CVE-2020-6406", "CVE-2020-6407", "CVE-2020-6408", "CVE-2020-6409", "CVE-2020-6410", "CVE-2020-6411", "CVE-2020-6412", "CVE-2020-6413", "CVE-2020-6414", "CVE-2020-6415", "CVE-2020-6416", "CVE-2020-6418", "CVE-2020-6420");
  script_xref(name:"DSA", value:"4638");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0023");

  script_name(english:"Debian DSA-4638-1 : chromium - security update");
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

  - CVE-2019-19880
    Richard Lorenz discovered an issue in the sqlite
    library.

  - CVE-2019-19923
    Richard Lorenz discovered an out-of-bounds read issue in
    the sqlite library.

  - CVE-2019-19925
    Richard Lorenz discovered an issue in the sqlite
    library.

  - CVE-2019-19926
    Richard Lorenz discovered an implementation error in the
    sqlite library.

  - CVE-2020-6381
    UK's National Cyber Security Centre discovered an
    integer overflow issue in the v8 JavaScript library.

  - CVE-2020-6382
    Soyeon Park and Wen Xu discovered a type error in the v8
    JavaScript library.

  - CVE-2020-6383
    Sergei Glazunov discovered a type error in the v8
    JavaScript library.

  - CVE-2020-6384
    David Manoucheri discovered a use-after-free issue in
    WebAudio.

  - CVE-2020-6385
    Sergei Glazunov discovered a policy enforcement error.

  - CVE-2020-6386
    Zhe Jin discovered a use-after-free issue in speech
    processing.

  - CVE-2020-6387
    Natalie Silvanovich discovered an out-of-bounds write
    error in the WebRTC implementation.

  - CVE-2020-6388
    Sergei Glazunov discovered an out-of-bounds read error
    in the WebRTC implementation.

  - CVE-2020-6389
    Natalie Silvanovich discovered an out-of-bounds write
    error in the WebRTC implementation.

  - CVE-2020-6390
    Sergei Glazunov discovered an out-of-bounds read error.

  - CVE-2020-6391
    Michal Bentkowski discoverd that untrusted input was
    insufficiently validated.

  - CVE-2020-6392
    The Microsoft Edge Team discovered a policy enforcement
    error.

  - CVE-2020-6393
    Mark Amery discovered a policy enforcement error.

  - CVE-2020-6394
    Phil Freo discovered a policy enforcement error.

  - CVE-2020-6395
    Pierre Langlois discovered an out-of-bounds read error
    in the v8 JavaScript library.

  - CVE-2020-6396
    William Luc Ritchie discovered an error in the skia
    library.

  - CVE-2020-6397
    Khalil Zhani discovered a user interface error.

  - CVE-2020-6398
    pdknsk discovered an uninitialized variable in the
    pdfium library.

  - CVE-2020-6399
    Luan Herrera discovered a policy enforcement error.

  - CVE-2020-6400
    Takashi Yoneuchi discovered an error in Cross-Origin
    Resource Sharing.

  - CVE-2020-6401
    Tzachy Horesh discovered that user input was
    insufficiently validated.

  - CVE-2020-6402
    Vladimir Metnew discovered a policy enforcement error.

  - CVE-2020-6403
    Khalil Zhani discovered a user interface error.

  - CVE-2020-6404
    kanchi discovered an error in Blink/Webkit.

  - CVE-2020-6405
    Yongheng Chen and Rui Zhong discovered an out-of-bounds
    read issue in the sqlite library.

  - CVE-2020-6406
    Sergei Glazunov discovered a use-after-free issue.

  - CVE-2020-6407
    Sergei Glazunov discovered an out-of-bounds read error.

  - CVE-2020-6408
    Zhong Zhaochen discovered a policy enforcement error in
    Cross-Origin Resource Sharing.

  - CVE-2020-6409
    Divagar S and Bharathi V discovered an error in the
    omnibox implementation.

  - CVE-2020-6410
    evil1m0 discovered a policy enforcement error.

  - CVE-2020-6411
    Khalil Zhani discovered that user input was
    insufficiently validated.

  - CVE-2020-6412
    Zihan Zheng discovered that user input was
    insufficiently validated.

  - CVE-2020-6413
    Michal Bentkowski discovered an error in Blink/Webkit.

  - CVE-2020-6414
    Lijo A.T discovered a policy safe browsing policy
    enforcement error.

  - CVE-2020-6415
    Avihay Cohen discovered an implementation error in the
    v8 JavaScript library.

  - CVE-2020-6416
    Woojin Oh discovered that untrusted input was
    insufficiently validated.

  - CVE-2020-6418
    Clement Lecigne discovered a type error in the v8
    JavaScript library.

  - CVE-2020-6420
    Taras Uzdenov discovered a policy enforcement error."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-19880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-19923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-19925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-19926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6411"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6413"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2020-6420"
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
    value:"https://www.debian.org/security/2020/dsa-4638"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium packages.

For the oldstable distribution (stretch), security support for
chromium has been discontinued.

For the stable distribution (buster), these problems have been fixed
in version 80.0.3987.132-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6420");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Google Chrome 80 JSCreate side-effect type confusion exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"chromium", reference:"80.0.3987.132-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-common", reference:"80.0.3987.132-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-driver", reference:"80.0.3987.132-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-l10n", reference:"80.0.3987.132-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-sandbox", reference:"80.0.3987.132-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-shell", reference:"80.0.3987.132-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
