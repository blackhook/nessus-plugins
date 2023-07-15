#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4182. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(109411);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/07/05");

  script_cve_id("CVE-2018-6056", "CVE-2018-6057", "CVE-2018-6060", "CVE-2018-6061", "CVE-2018-6062", "CVE-2018-6063", "CVE-2018-6064", "CVE-2018-6065", "CVE-2018-6066", "CVE-2018-6067", "CVE-2018-6068", "CVE-2018-6069", "CVE-2018-6070", "CVE-2018-6071", "CVE-2018-6072", "CVE-2018-6073", "CVE-2018-6074", "CVE-2018-6075", "CVE-2018-6076", "CVE-2018-6077", "CVE-2018-6078", "CVE-2018-6079", "CVE-2018-6080", "CVE-2018-6081", "CVE-2018-6082", "CVE-2018-6083", "CVE-2018-6085", "CVE-2018-6086", "CVE-2018-6087", "CVE-2018-6088", "CVE-2018-6089", "CVE-2018-6090", "CVE-2018-6091", "CVE-2018-6092", "CVE-2018-6093", "CVE-2018-6094", "CVE-2018-6095", "CVE-2018-6096", "CVE-2018-6097", "CVE-2018-6098", "CVE-2018-6099", "CVE-2018-6100", "CVE-2018-6101", "CVE-2018-6102", "CVE-2018-6103", "CVE-2018-6104", "CVE-2018-6105", "CVE-2018-6106", "CVE-2018-6107", "CVE-2018-6108", "CVE-2018-6109", "CVE-2018-6110", "CVE-2018-6111", "CVE-2018-6112", "CVE-2018-6113", "CVE-2018-6114", "CVE-2018-6116", "CVE-2018-6117");
  script_xref(name:"DSA", value:"4182");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"Debian DSA-4182-1 : chromium-browser - security update");
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

  - CVE-2018-6056
    lokihardt discovered an error in the v8 JavaScript
    library.

  - CVE-2018-6057
    Gal Beniamini discovered errors related to shared memory
    permissions.

  - CVE-2018-6060
    Omair discovered a use-after-free issue in blink/webkit.

  - CVE-2018-6061
    Guang Gong discovered a race condition in the v8
    JavaScript library.

  - CVE-2018-6062
    A heap overflow issue was discovered in the v8
    JavaScript library.

  - CVE-2018-6063
    Gal Beniamini discovered errors related to shared memory
    permissions.

  - CVE-2018-6064
    lokihardt discovered a type confusion error in the v8
    JavaScript library.

  - CVE-2018-6065
    Mark Brand discovered an integer overflow issue in the
    v8 JavaScript library.

  - CVE-2018-6066
    Masato Kinugawa discovered a way to bypass the Same
    Origin Policy.

  - CVE-2018-6067
    Ned Williamson discovered a buffer overflow issue in the
    skia library.

  - CVE-2018-6068
    Luan Herrera discovered object lifecycle issues.

  - CVE-2018-6069
    Wanglu and Yangkang discovered a stack overflow issue in
    the skia library.

  - CVE-2018-6070
    Rob Wu discovered a way to bypass the Content Security
    Policy.

  - CVE-2018-6071
    A heap overflow issue was discovered in the skia
    library.

  - CVE-2018-6072
    Atte Kettunen discovered an integer overflow issue in
    the pdfium library.

  - CVE-2018-6073
    Omair discover a heap overflow issue in the WebGL
    implementation.

  - CVE-2018-6074
    Abdulrahman Alqabandi discovered a way to cause a
    downloaded web page to not contain a Mark of the Web.

  - CVE-2018-6075
    Inti De Ceukelaire discovered a way to bypass the Same
    Origin Policy.

  - CVE-2018-6076
    Mateusz Krzeszowiec discovered that URL fragment
    identifiers could be handled incorrectly.

  - CVE-2018-6077
    Khalil Zhani discovered a timing issue.

  - CVE-2018-6078
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6079
    Ivars discovered an information disclosure issue.

  - CVE-2018-6080
    Gal Beniamini discovered an information disclosure
    issue.

  - CVE-2018-6081
    Rob Wu discovered a cross-site scripting issue.

  - CVE-2018-6082
    WenXu Wu discovered a way to bypass blocked ports.

  - CVE-2018-6083
    Jun Kokatsu discovered that AppManifests could be
    handled incorrectly.

  - CVE-2018-6085
    Ned Williamson discovered a use-after-free issue.

  - CVE-2018-6086
    Ned Williamson discovered a use-after-free issue.

  - CVE-2018-6087
    A use-after-free issue was discovered in the WebAssembly
    implementation.

  - CVE-2018-6088
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2018-6089
    Rob Wu discovered a way to bypass the Same Origin
    Policy.

  - CVE-2018-6090
    ZhanJia Song discovered a heap overflow issue in the
    skia library.

  - CVE-2018-6091
    Jun Kokatsu discovered that plugins could be handled
    incorrectly.

  - CVE-2018-6092
    Natalie Silvanovich discovered an integer overflow issue
    in the WebAssembly implementation.

  - CVE-2018-6093
    Jun Kokatsu discovered a way to bypass the Same Origin
    Policy.

  - CVE-2018-6094
    Chris Rohlf discovered a regression in garbage
    collection hardening.

  - CVE-2018-6095
    Abdulrahman Alqabandi discovered files could be uploaded
    without user interaction.

  - CVE-2018-6096
    WenXu Wu discovered a user interface spoofing issue.

  - CVE-2018-6097
    xisigr discovered a user interface spoofing issue.

  - CVE-2018-6098
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6099
    Jun Kokatsu discovered a way to bypass the Cross Origin
    Resource Sharing mechanism.

  - CVE-2018-6100
    Lnyas Zhang discovered a URL spoofing issue.

  - CVE-2018-6101
    Rob Wu discovered an issue in the developer tools remote
    debugging protocol.

  - CVE-2018-6102
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6103
    Khalil Zhani discovered a user interface spoofing issue.

  - CVE-2018-6104
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6105
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6106
    lokihardt discovered that v8 promises could be handled
    incorrectly.

  - CVE-2018-6107
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6108
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6109
    Dominik Weber discovered a way to misuse the FileAPI
    feature.

  - CVE-2018-6110
    Wenxiang Qian discovered that local plain text files
    could be handled incorrectly.

  - CVE-2018-6111
    Khalil Zhani discovered a use-after-free issue in the
    developer tools.

  - CVE-2018-6112
    Khalil Zhani discovered incorrect handling of URLs in
    the developer tools.

  - CVE-2018-6113
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2018-6114
    Lnyas Zhang discovered a way to bypass the Content
    Security Policy.

  - CVE-2018-6116
    Chengdu Security Response Center discovered an error
    when memory is low.

  - CVE-2018-6117
    Spencer Dailey discovered an error in form autofill
    settings."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6086"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6090"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6091"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-6117"
  );
  # https://security-tracker.debian.org/tracker/source-package/chromium-browser
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e33901a2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2018/dsa-4182"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium-browser packages.

For the oldstable distribution (jessie), security support for chromium
has been discontinued.

For the stable distribution (stretch), these problems have been fixed
in version 66.0.3359.117-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6111");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"66.0.3359.117-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"66.0.3359.117-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"66.0.3359.117-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"66.0.3359.117-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"66.0.3359.117-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"66.0.3359.117-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
