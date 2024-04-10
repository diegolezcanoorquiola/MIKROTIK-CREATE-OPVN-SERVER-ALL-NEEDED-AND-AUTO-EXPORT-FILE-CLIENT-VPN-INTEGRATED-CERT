#dl240409 git: https://github.com/diegolezcanoorquiola/MIKROTIK-CREATE-OPVN-SERVER-ALL-NEEDED-AND-AUTO-EXPORT-FILE-CLIENT-VPN-INTEGRATED-CERT.git

# Setup OpenVPN Server and generate certs and export ovpn config cert integrate and setable v6 v7 
#
# Change variables below and paste the script
# into MikroTik terminal window.
#
#######################################################################################################

######## VERSION OR RouterOS. VALUES VALIDS: "V6" OR  "V7"
:global ROUTEROSVERSION "V7"

######## PARAMETROS DEL CA CERTIFICADOR ###############################################################

# TAMAÑO DEL RSA CIFRADO 2048 EN ADELANTE SE RECOMIENDA, NO MODIFICARLO DE NO SER NECESARIO.
:global CN [/system identity get name]
:global COUNTRY "PY"
:global STATE "CENTRAL"
:global LOC "MACDONALS"
:global ORG "MACDONALS"
:global OU ""
:global KEYSIZE "2048"


#################### PARAMETROS PARA LA CREACION DEL TUNEL OVPN ######################################

# IPP DE BORDE POR LA QUE SE ACCEDE AL OVPN SERVER SEA LA IP PUBLICA (EN ESTE EJ: LA IPP DE GOOGLE) DEL MIKROTIK O UNA IP DE UN SEGMENTO EN EL CASO DE SUBSEGMENTOS.
:global SERVERADDRESS "1.1.1.1"



#################### PARAMETROS PARA LA CREACION DEL USUARIO OVPN ######################################

# EDITABLE POR EL TECNICO (OBLIGATORIO):  USUARIO/OS CONTRASEÑA/AS A CREAR, LOS USARIOS SE DEBEN CARGAR EN EL ARRAY DE MANERA DESCENDENTE EJ: DEL ULTIMO AL PRIMER USUARIO, PARA QUE AL EXPLORTAR LOS FILES.OVPN, EL PRIMERO CREADO (O EL NUMERO MAS BAJO)SEA EL ULTIMO QUE FUE EL USUARIO1, LA CONTRASEÑA DEBE COMPLIR CON EL STANDAR DE COMPLEJIDAD ACTUAL DE MÁS DE 8 CARACTERES ALEATORIO MAYUS MIN CARACTERES ESPECIALES NUMERICOS, ESCAPAR LOS CARACTERES ESPECIALES EJ: "$" CON "\" "\$"".
:global OVPNUSERS {"contabilidad3"="SuayuysTDTS\$ga253tagh";"contabilidad2"="HAjuiASUAS\$123";"contabilidad1"="iasdfbUASYas35asdaA"}



#################### PARAMETROS PARA LA CREACION DEL PERFIL OVPN SERVER. ######################################

# EDITABLE POR EL TECNICO (OBLIGATORIO):  NOMBRE REPRENTATIVO DEL TUNEL VPN EJ: OVPN-MACDONALS
:global VPNPROFILE "OVPN-MACDONALS"

# EDITABLE POR EL TECNICO (RECOMENDADORECOMENDADO/OBLIGATORIO EN CASOS DONDE YA EXISTA LA MISMA PUERTA PARA OTRO INTERFAZ): IP DE LA PUERTA DE ENLACE PARA LAS CONSULTAS DEL OVPN.
:global LOCALADDRESS "10.10.0.1"

# EDITABLE POR EL TECNICO (RECOMENDADO/OBLIGATORIO EN CASOS DONDE YA EXISTA EL MISMO POOL): VALOR DE INICIO DEL POOL POR NORMA LA PUERTA LA PRIMERA IP, LUEGO EL PRIMER HOST, SOLO DECLARAR LOS BITS DEL HOST NO DE SEGMENTO EJ: 2 SIENDO 1 LA PUERTA Y NO 10.10.0.2
:global FIRSTHOST "2"

#NO SE RECOMIENDA EDITAR : CALCULA AUTOMATICAMENTE LA CANTIDAD DE HOST DEL POOL VPN CONFORME A LA CANTIDAD DE USUARIOS DECLARADOS EN EL ARRAR $OVPNUSERS.
:global LASTHOST [:len ($OVPNUSERS+1)];

#RANGO DE DIRECCIONES A SER ASIGNADOS A LOS USUARIOS DEL TUNEL.
:global POOLVPN "10.10.0.$FIRSTHOST-10.10.0.$LASTHOST"

# EDITABLE POR EL TECNICO : Mascara a ser aplicada al cliente OVPN.
:global NETMASK 24



#RESCRIBE LA TABLA DE RUTEO DEL CLIENTE PARA INCLUIRSE COMO RESOLUTOR SECUNDARIO. DISABLED DEFAULT PARA SPLIT TUNNEL.
:if ($ROUTEROSVERSION="V7") do={[:global REDIRECTGATEWAY "disabled"]}


#EN TEORIA DEBERIA DE AGREGAR EL ALCANCE A LA RUTA ESPECIFICADA EN EL FORMATO NET MASK GATEWAY METRIC.
:if ($ROUTEROSVERSION="V7") do={[:global PUSHROUTES "192.168.0.22"]}

#TIPO DE CIFRADO, EL MÁS ALTO COMPATIBLE POR AMBOS PUNTOS, NO MODIFICARLO DE NO SER NECESARIO.
:global CIPHER "aes256-cbc"

# COMPLEJIDAD DEL CIFRADO PARA LA AUTENTICACION DEL USUARIO, SE RECOMIENDA LA MÁS ALTA COMPATIBLE.
:if ($ROUTEROSVERSION="V7") do={[:global AUTHOVPN "sha512"]} else={[:global AUTHOVPN "sha1"]}



##########################################################################################################################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################
#                                                                             SCRIPT 
#                    RECOMENDACION: NO MODIFICAR DE NO SER NECESARIO O NO ESTAR SEGURO DE PODER HACERLO, HACIENDO SIEMPRE UNA COPIA ANTES MODIFICAR ALGO






## functions
:global waitSec do={:return ($KEYSIZE * 10 / 1024)}



## generate a CA certificate
/certificate
add name=ca-template country="$COUNTRY" state="$STATE" locality="$LOC" organization="$ORG" unit="$OU" common-name="$CN" key-size="$KEYSIZE" days-valid=3650 key-usage=crl-sign,key-cert-sign
sign ca-template ca-crl-host=127.0.0.1 name="$CN"
:delay [$waitSec]

## generate a server certificate
/certificate
add name=server-template country="$COUNTRY" state="$STATE" locality="$LOC" organization="$ORG" unit="$OU" common-name="server@$CN" key-size="$KEYSIZE" days-valid=3650 key-usage=digital-signature,key-encipherment,tls-server
sign server-template ca="$CN" name="server@$CN"
:delay [$waitSec]

## create a client template
/certificate
add name=client-template country="$COUNTRY" state="$STATE" locality="$LOC" organization="$ORG" unit="$OU" common-name="client" key-size="$KEYSIZE" days-valid=3650 key-usage=tls-client

## create IP pool
/ip pool
add name="VPN-POOL-$VPNPROFILE" ranges=$POOLVPN

## add VPN profile
/ppp profile
add local-address=$LOCALADDRESS name="VPN-PROFILE-$VPNPROFILE" remote-address="VPN-POOL-$VPNPROFILE" use-encryption="yes" 

## setup OpenVPN server
/interface ovpn-server server
:if ($ROUTEROSVERSION="V7") do={[set auth="$AUTHOVPN" certificate="server@$CN" cipher="$CIPHER" default-profile="VPN-PROFILE-$VPNPROFILE" enabled="yes" mode="ip" netmask=$NETMASK require-client-certificate="yes" push-routes="$PUSHROUTES" redirect-gateway=$REDIRECTGATEWAY]} else={[set auth="$AUTHOVPN" certificate="server@$CN" cipher="$CIPHER" default-profile="VPN-PROFILE-$VPNPROFILE" enabled="yes" mode="ip" netmask=$NETMASK require-client-certificate="yes"]}

## add a firewall rule
/ip firewall filter
add chain=input dst-port=1194 protocol=tcp comment="Allow-OpenVPN-$VPNPROFILE" place-before=1

###################################################################################################################################

################################ Add a new user and generate/export certs #########################################################


## add a user/USERS
/ppp secret
:foreach k,v in=$OVPNUSERS do={[add name=$k password=$v profile="VPN-PROFILE-$VPNPROFILE" service=ovpn]}

## generate a client certificate
/certificate
:foreach k,v in=$OVPNUSERS do={[add name=client-template-to-issue copy-from="client-template" common-name="$k@$CN";sign client-template-to-issue ca="$CN" name="$k@$CN";:delay 20]}


## export the CA, client certificate.
/certificate
export-certificate "$CN" export-passphrase="";
# EXPORT USERS and private key.
:foreach k,v in=$OVPNUSERS do={[export-certificate "$k@$CN" export-passphrase="$v";:delay 20;]}



## EXPORTAR LA CONFIGURACION DEL CLIENTE OVPN.
/interface ovpn-server server
:if ($ROUTEROSVERSION="V7") do={[:foreach k,v in=$OVPNUSERS do={[export-client-configuration server-address=$SERVERADDRESS ca-certificate="cert_export_$CN.crt" client-certificate="cert_export_$k@$CN.crt" client-cert-key="cert_export_$k@$CN.key";:delay 20]}]}
/
:put "TL: FIN DEL PROCESO CREATE OVPN..."





