#!/usr/bin/env bash
set -eu
. /opt/bitnami/scripts/libopenldap.sh

trap ldap_stop EXIT
ldap_start_bg

ldapmodify -Y EXTERNAL -H "ldapi:///" -f /docker-entrypoint-initdb.d/set_acl.ldif