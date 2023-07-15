#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('compat.inc');

if (description)
{
  script_id(137382);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-8172",
    "CVE-2020-8174",
    "CVE-2020-10531",
    "CVE-2020-11080"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"FreeBSD : Node.js -- June 2020 Security Releases (11fcfa8f-ac64-11ea-9dab-000d3ab229d6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"Node.js reports :

Updates are now available for all supported Node.js release lines for
the following issues. TLS session reuse can lead to host certificate
verification bypass (High) (CVE-2020-8172) The 'session' event could
be emitted before the 'secureConnect' event. It should not be, because
the connection may fail to be authorized. If it was saved an
authorized connection could be established later with the session
ticket. Note that the https agent caches sessions, so is vulnerable to
this.

The 'session' event will now only be emitted after the 'secureConnect'
event, and only for authorized connections. HTTP/2 Large Settings
Frame DoS (Low) (CVE-2020-11080) Receiving unreasonably large HTTP/2
SETTINGS frames can consume 100% CPU to process all the settings,
blocking all other activities until complete.

The HTTP/2 session frame is limited to 32 settings by default. This
can be configured if necessary using the maxSettings option.
napi_get_value_string_*() allows various kinds of memory corruption
(High) (CVE-2020-8174) Calling napi_get_value_string_latin1(),
napi_get_value_string_utf8(), or napi_get_value_string_utf16() with a
non-NULL buf, and a bufsize of 0 will cause the entire string value to
be written to buf, probably overrunning the length of the buffer.

A exploit has not been reported and it may be difficult but the
following is suggested :

- All users of LTS Node.js versions should update to the versions
announced in this security post. This will address the issue for any
non pre-built add-on.

- Maintainers who support EOL Node.js versions and/or build against a
version of Node.js that did not support N-API internally should update
to use the new versions of node-addon-api 1.x and 2.x that will be
released soon after this announcement. ICU-20958 Prevent SEGV_MAPERR
in append (High) (CVE-2020-10531) An issue was discovered in
International Components for Unicode (ICU) for C/C++ through 66.1. An
integer overflow, leading to a heap-based buffer overflow, exists in
the UnicodeString::doAppend() function in common/unistr.cpp.

Fix was applied to 10.x in an abundance of caution, even though there
is no known way to trigger the overflow in 10.x.");
  script_set_attribute(attribute:"see_also", value:"https://nodejs.org/en/blog/vulnerability/june-2020-security-releases/");
  # https://vuxml.freebsd.org/freebsd/11fcfa8f-ac64-11ea-9dab-000d3ab229d6.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2156d528");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8174");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-10531");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"node<14.4.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node12<12.18.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node10<10.21.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
