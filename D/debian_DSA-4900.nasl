#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4900. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(149011);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2021-3497", "CVE-2021-3498");
  script_xref(name:"DSA", value:"4900");

  script_name(english:"Debian DSA-4900-1 : gst-plugins-good1.0 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities were discovered in plugins for the GStreamer
media framework, which may result in denial of service or potentially
the execution of arbitrary code if a malformed media file is opened."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=986910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=986911"
  );
  # https://security-tracker.debian.org/tracker/source-package/gst-plugins-good1.0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91533ee1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/gst-plugins-good1.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4900"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the gst-plugins-good1.0 packages.

For the stable distribution (buster), these problems have been fixed
in version 1.14.4-1+deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3498");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gst-plugins-good1.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"10.0", prefix:"gstreamer1.0-gtk3", reference:"1.14.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gstreamer1.0-plugins-good", reference:"1.14.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gstreamer1.0-plugins-good-dbg", reference:"1.14.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gstreamer1.0-plugins-good-doc", reference:"1.14.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gstreamer1.0-pulseaudio", reference:"1.14.4-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gstreamer1.0-qt5", reference:"1.14.4-1+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
