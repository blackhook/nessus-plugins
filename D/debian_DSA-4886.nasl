#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4886. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148364);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2021-21159", "CVE-2021-21160", "CVE-2021-21161", "CVE-2021-21162", "CVE-2021-21163", "CVE-2021-21165", "CVE-2021-21166", "CVE-2021-21167", "CVE-2021-21168", "CVE-2021-21169", "CVE-2021-21170", "CVE-2021-21171", "CVE-2021-21172", "CVE-2021-21173", "CVE-2021-21174", "CVE-2021-21175", "CVE-2021-21176", "CVE-2021-21177", "CVE-2021-21178", "CVE-2021-21179", "CVE-2021-21180", "CVE-2021-21181", "CVE-2021-21182", "CVE-2021-21183", "CVE-2021-21184", "CVE-2021-21185", "CVE-2021-21186", "CVE-2021-21187", "CVE-2021-21188", "CVE-2021-21189", "CVE-2021-21190", "CVE-2021-21191", "CVE-2021-21192", "CVE-2021-21193", "CVE-2021-21194", "CVE-2021-21195", "CVE-2021-21196", "CVE-2021-21197", "CVE-2021-21198", "CVE-2021-21199");
  script_xref(name:"DSA", value:"4886");
  script_xref(name:"IAVA", value:"2021-A-0152-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");

  script_name(english:"Debian DSA-4886-1 : chromium - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilites have been discovered in the chromium web
browser.

  - CVE-2021-21159
    Khalil Zhani discovered a buffer overflow issue in the
    tab implementation.

  - CVE-2021-21160
    Marcin Noga discovered a buffer overflow issue in
    WebAudio.

  - CVE-2021-21161
    Khalil Zhani discovered a buffer overflow issue in the
    tab implementation.

  - CVE-2021-21162
    A use-after-free issue was discovered in the WebRTC
    implementation.

  - CVE-2021-21163
    Alison Huffman discovered a data validation issue.

  - CVE-2021-21165
    Alison Huffman discovered an error in the audio
    implementation.

  - CVE-2021-21166
    Alison Huffman discovered an error in the audio
    implementation.

  - CVE-2021-21167
    Leecraso and Guang Gong discovered a use-after-free
    issue in the bookmarks implementation.

  - CVE-2021-21168
    Luan Herrera discovered a policy enforcement error in
    the appcache.

  - CVE-2021-21169
    Bohan Liu and Moon Liang discovered an out-of-bounds
    access issue in the v8 JavaScript library.

  - CVE-2021-21170
    David Erceg discovered a user interface error.

  - CVE-2021-21171
    Irvan Kurniawan discovered a user interface error.

  - CVE-2021-21172
    Maciej Pulikowski discovered a policy enforcement error
    in the File System API.

  - CVE-2021-21173
    Tom Van Goethem discovered a network based information
    leak.

  - CVE-2021-21174
    Ashish Guatam Kambled discovered an implementation error
    in the Referrer policy.

  - CVE-2021-21175
    Jun Kokatsu discovered an implementation error in the
    Site Isolation feature.

  - CVE-2021-21176
    Luan Herrera discovered an implementation error in the
    full screen mode.

  - CVE-2021-21177
    Abdulrahman Alqabandi discovered a policy enforcement
    error in the Autofill feature.

  - CVE-2021-21178
    Japong discovered an error in the Compositor
    implementation.

  - CVE-2021-21179
    A use-after-free issue was discovered in the networking
    implementation.

  - CVE-2021-21180
    Abdulrahman Alqabandi discovered a use-after-free issue
    in the tab search feature.

  - CVE-2021-21181
    Xu Lin, Panagiotis Ilias, and Jason Polakis discovered a
    side-channel information leak in the Autofill feature.

  - CVE-2021-21182
    Luan Herrera discovered a policy enforcement error in
    the site navigation implementation.

  - CVE-2021-21183
    Takashi Yoneuchi discovered an implementation error in
    the Performance API.

  - CVE-2021-21184
    James Hartig discovered an implementation error in the
    Performance API.

  - CVE-2021-21185
    David Erceg discovered a policy enforcement error in
    Extensions.

  - CVE-2021-21186
    dhirajkumarnifty discovered a policy enforcement error
    in the QR scan implementation.

  - CVE-2021-21187
    Kirtikumar Anandrao Ramchandani discovered a data
    validation error in URL formatting.

  - CVE-2021-21188
    Woojin Oh discovered a use-after-free issue in
    Blink/Webkit.

  - CVE-2021-21189
    Khalil Zhani discovered a policy enforcement error in
    the Payments implementation.

  - CVE-2021-21190
    Zhou Aiting discovered use of uninitialized memory in
    the pdfium library.

  - CVE-2021-21191
    raven discovered a use-after-free issue in the WebRTC
    implementation.

  - CVE-2021-21192
    Abdulrahman Alqabandi discovered a buffer overflow issue
    in the tab implementation.

  - CVE-2021-21193
    A use-after-free issue was discovered in Blink/Webkit.

  - CVE-2021-21194
    Leecraso and Guang Gong discovered a use-after-free
    issue in the screen capture feature.

  - CVE-2021-21195
    Liu and Liang discovered a use-after-free issue in the
    v8 JavaScript library.

  - CVE-2021-21196
    Khalil Zhani discovered a buffer overflow issue in the
    tab implementation.

  - CVE-2021-21197
    Abdulrahman Alqabandi discovered a buffer overflow issue
    in the tab implementation.

  - CVE-2021-21198
    Mark Brand discovered an out-of-bounds read issue in the
    Inter-Process Communication implementation.

  - CVE-2021-21199
    Weipeng Jiang discovered a use-after-free issue in the
    Aura window and event manager."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2021-21199"
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
    value:"https://www.debian.org/security/2021/dsa-4886"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the chromium packages.

For the stable distribution (buster), these problems have been fixed
in version 89.0.4389.114-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21199");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"chromium", reference:"89.0.4389.114-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-common", reference:"89.0.4389.114-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-driver", reference:"89.0.4389.114-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-l10n", reference:"89.0.4389.114-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-sandbox", reference:"89.0.4389.114-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-shell", reference:"89.0.4389.114-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
