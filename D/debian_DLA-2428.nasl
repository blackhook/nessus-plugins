#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2428-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(142155);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/06");

  script_cve_id("CVE-2020-14355");

  script_name(english:"Debian DLA-2428-1 : spice-gtk security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple buffer overflow vulnerabilities were found in the QUIC image
decoding process of the SPICE remote display system.

Both the SPICE client (spice-gtk) and server are affected by these
flaws. These flaws allow a malicious client or server to send
specially crafted messages that, when processed by the QUIC image
compression algorithm, result in a process crash or potential code
execution.

For Debian 9 stretch, this problem has been fixed in version
0.33-3.3+deb9u2.

We recommend that you upgrade your spice-gtk packages.

For the detailed security status of spice-gtk please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/spice-gtk

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/spice-gtk"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/spice-gtk"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14355");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-spice-client-glib-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-spice-client-gtk-3.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspice-client-glib-2.0-8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspice-client-glib-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspice-client-gtk-3.0-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libspice-client-gtk-3.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spice-client-glib-usb-acl-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spice-client-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");
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
if (deb_check(release:"9.0", prefix:"gir1.2-spice-client-glib-2.0", reference:"0.33-3.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gir1.2-spice-client-gtk-3.0", reference:"0.33-3.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libspice-client-glib-2.0-8", reference:"0.33-3.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libspice-client-glib-2.0-dev", reference:"0.33-3.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libspice-client-gtk-3.0-5", reference:"0.33-3.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libspice-client-gtk-3.0-dev", reference:"0.33-3.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"spice-client-glib-usb-acl-helper", reference:"0.33-3.3+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"spice-client-gtk", reference:"0.33-3.3+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
