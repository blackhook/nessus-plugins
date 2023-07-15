#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
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
  script_id(174334);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id("CVE-2014-3641");

  script_name(english:"FreeBSD : py-cinder -- data leak (f4a94232-7864-4afb-bbf9-ff2dc8e288d1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the f4a94232-7864-4afb-bbf9-ff2dc8e288d1 advisory.

  - The (1) GlusterFS and (2) Linux Smbfs drivers in OpenStack Cinder before 2014.1.3 allows remote
    authenticated users to obtain file data from the Cinder-volume host by cloning and attaching a volume with
    a crafted qcow2 header. (CVE-2014-3641)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://osv.dev/vulnerability/GHSA-qhch-g8qr-p497");
  # https://vuxml.freebsd.org/freebsd/f4a94232-7864-4afb-bbf9-ff2dc8e288d1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?517a3573");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3641");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py310-cinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py311-cinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-cinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-cinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py39-cinder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'py310-cinder<=12.0.9',
    'py310-cinder>=13.0.0<13.0.9',
    'py310-cinder>=14.0.0<14.3.1',
    'py310-cinder>=15.0.0<15.6.0',
    'py310-cinder>=16.0.0<16.4.2',
    'py310-cinder>=17.0.0<17.4.0',
    'py310-cinder>=18.0.0<18.2.1',
    'py310-cinder>=19.0.0<19.2.0',
    'py310-cinder>=20.0.0<20.1.0',
    'py310-cinder>=21.0.0<21.1.0',
    'py310-cinder>=22.0.0<22.0.0.0rc2',
    'py311-cinder<=12.0.9',
    'py311-cinder>=13.0.0<13.0.9',
    'py311-cinder>=14.0.0<14.3.1',
    'py311-cinder>=15.0.0<15.6.0',
    'py311-cinder>=16.0.0<16.4.2',
    'py311-cinder>=17.0.0<17.4.0',
    'py311-cinder>=18.0.0<18.2.1',
    'py311-cinder>=19.0.0<19.2.0',
    'py311-cinder>=20.0.0<20.1.0',
    'py311-cinder>=21.0.0<21.1.0',
    'py311-cinder>=22.0.0<22.0.0.0rc2',
    'py37-cinder<=12.0.9',
    'py37-cinder>=13.0.0<13.0.9',
    'py37-cinder>=14.0.0<14.3.1',
    'py37-cinder>=15.0.0<15.6.0',
    'py37-cinder>=16.0.0<16.4.2',
    'py37-cinder>=17.0.0<17.4.0',
    'py37-cinder>=18.0.0<18.2.1',
    'py37-cinder>=19.0.0<19.2.0',
    'py37-cinder>=20.0.0<20.1.0',
    'py37-cinder>=21.0.0<21.1.0',
    'py37-cinder>=22.0.0<22.0.0.0rc2',
    'py38-cinder<=12.0.9',
    'py38-cinder>=13.0.0<13.0.9',
    'py38-cinder>=14.0.0<14.3.1',
    'py38-cinder>=15.0.0<15.6.0',
    'py38-cinder>=16.0.0<16.4.2',
    'py38-cinder>=17.0.0<17.4.0',
    'py38-cinder>=18.0.0<18.2.1',
    'py38-cinder>=19.0.0<19.2.0',
    'py38-cinder>=20.0.0<20.1.0',
    'py38-cinder>=21.0.0<21.1.0',
    'py38-cinder>=22.0.0<22.0.0.0rc2',
    'py39-cinder<=12.0.9',
    'py39-cinder>=13.0.0<13.0.9',
    'py39-cinder>=14.0.0<14.3.1',
    'py39-cinder>=15.0.0<15.6.0',
    'py39-cinder>=16.0.0<16.4.2',
    'py39-cinder>=17.0.0<17.4.0',
    'py39-cinder>=18.0.0<18.2.1',
    'py39-cinder>=19.0.0<19.2.0',
    'py39-cinder>=20.0.0<20.1.0',
    'py39-cinder>=21.0.0<21.1.0',
    'py39-cinder>=22.0.0<22.0.0.0rc2'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
