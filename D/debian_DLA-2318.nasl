#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2318-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(139429);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-10064", "CVE-2020-12695");
  script_xref(name:"CEA-ID", value:"CEA-2020-0050");

  script_name(english:"Debian DLA-2318-1 : wpa security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The following CVE(s) have been reported against src:wpa.

CVE-2019-10064

hostapd before 2.6, in EAP mode, makes calls to the rand() and
random() standard library functions without any preceding srand() or
srandom() call, which results in inappropriate use of deterministic
values. This was fixed in conjunction with CVE-2016-10743.

CVE-2020-12695

The Open Connectivity Foundation UPnP specification before 2020-04-17
does not forbid the acceptance of a subscription request with a
delivery URL on a different network segment than the fully qualified
event-subscription URL, aka the CallStranger issue.

For Debian 9 stretch, these problems have been fixed in version
2:2.4-1+deb9u7.

We recommend that you upgrade your wpa packages.

For the detailed security status of wpa please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/wpa

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/wpa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/wpa"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12695");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpagui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/10");
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
if (deb_check(release:"9.0", prefix:"hostapd", reference:"2:2.4-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"wpagui", reference:"2:2.4-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"wpasupplicant", reference:"2:2.4-1+deb9u7")) flag++;
if (deb_check(release:"9.0", prefix:"wpasupplicant-udeb", reference:"2:2.4-1+deb9u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
