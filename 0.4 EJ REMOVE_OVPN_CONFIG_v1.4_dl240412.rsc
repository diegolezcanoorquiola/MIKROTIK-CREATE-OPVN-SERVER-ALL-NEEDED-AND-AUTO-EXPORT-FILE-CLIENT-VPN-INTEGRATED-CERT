###################################################################################################

#dl240412 v1.4 git:https://github.com/diegolezcanoorquiola/MIKROTIK-CREATE-OPVN-SERVER-ALL-NEEDED-AND-AUTO-EXPORT-FILE-CLIENT-VPN-INTEGRATED-CERT

###################################################################################################


# REMOVE OVPN CONFIGURATION SCRIPT , Setup Default OpenVPN Server, firewall ovpn protocol, nat between ovpnpool and push-route, and generate certs, ppp profile, users vpn,  and export ovpn config cert integrate and setable v7, v6 cannot push-route and export clientconfig.ovpn 
#
# Change variables below and paste the script
# into MikroTik terminal window.
#
#######################################################################################################






###################################################################################################
# REMPLAZAR ESTE SEGMENTO CON LAS VARIABLES DEL SCRIPT DE CREACION PARA QUE PUEDA LOCALIZAR CORRECTAMENTE LAS CONFIGURACIONES A REMOVER.


######## VERSION OR RouterOS. VALUES VALIDS: "V6" OR  "V7"
:global ROUTEROSVERSION "V7"

######## PARAMETROS DEL CA CERTIFICADOR ###########################################################

# TAMAÑO DEL RSA CIFRADO 2048 EN ADELANTE SE RECOMIENDA, NO MODIFICARLO DE NO SER NECESARIO.
:global CN [/system identity get name]
:global COUNTRY "PY"
:global STATE "CENTRAL"
:global LOC "MACDONALS"
:global ORG "MACDONALS"
:global OU ""
:global KEYSIZE "2048"


#################### PARAMETROS PARA LA CREACION DEL TUNEL OVPN ###################################

# IPP DE BORDE POR LA QUE SE ACCEDE AL OVPN SERVER SEA LA IP PUBLICA DEL MIKROTIK O UNA IP DE UN SEGMENTO EN EL CASO DE SUBSEGMENTOS.
:global SERVERADDRESS "181.94.32.135"


#################### PARAMETROS PARA LA CREACION DEL USUARIO OVPN #################################

# EDITABLE POR EL TECNICO (OBLIGATORIO):  USUARIO/OS CONTRASEÑA/AS A CREAR, LOS USARIOS SE DEBEN CARGAR EN EL ARRAY DE MANERA DESCENDENTE EJ: DEL ULTIMO AL PRIMER USUARIO, PARA QUE AL EXPLORTAR LOS FILES.OVPN, EL PRIMERO CREADO (O EL NUMERO MAS BAJO)SEA EL ULTIMO QUE FUE EL USUARIO1, LA CONTRASEÑA DEBE COMPLIR CON EL STANDAR DE COMPLEJIDAD ACTUAL DE MÁS DE 8 CARACTERES ALEATORIO MAYUS MIN CARACTERES ESPECIALES NUMERICOS.
:global OVPNUSERS {"contabilidad3"="SuayasBD\$gasft4253tagh";"contabilidad2"="iauuasyYTRAvs\$66543aU";"contabilidad1"="iasdYasydaTu\$5as35asdaA"}

# "no" PERMITE QUE UN MISMO USUARIO SE LOGEE SIMULTANEAMENTE EN DIFERENTES DISPOSITIVOS, "yes" SOLO PERMITE UN LOGIN A LA VEZ POR USUARIO (RECOMENDADO)
:global ONLY-ONE "yes"


#################### PARAMETROS PARA LA CREACION DEL PERFIL OVPN SERVER. ##########################

# EDITABLE POR EL TECNICO (OBLIGATORIO):  NOMBRE REPRENTATIVO DEL TUNEL VPN EJ: OVPNBACUNOVICH
:global OVPNPROFILE "OVPN-MACDONALS"

# EDITABLE POR EL TECNICO (RECOMENDADORECOMENDADO/OBLIGATORIO EN CASOS DONDE YA EXISTA LA MISMA PUERTA PARA OTRO INTERFAZ): IP DE LA PUERTA DE ENLACE PARA LAS CONSULTAS DEL OVPN.
:global LOCALADDRESS "10.10.0.1"

# EDITABLE POR EL TECNICO (RECOMENDADO/OBLIGATORIO EN CASOS DONDE YA EXISTA EL MISMO POOL): VALOR DE INICIO DEL POOL POR NORMA LA PUERTA LA PRIMERA IP, LUEGO EL PRIMER HOST, SOLO DECLARAR LOS BITS DEL HOST NO DE SEGMENTO EJ: 2 SIENDO 1 LA PUERTA Y NO 10.10.0.2
:global FIRSTHOST "2"

#NO SE RECOMIENDA EDITAR : CALCULA AUTOMATICAMENTE LA CANTIDAD DE HOST DEL POOL VPN CONFORME A LA CANTIDAD DE USUARIOS DECLARADOS EN EL ARRAR $OVPNUSERS.
:global LASTHOST [:len ($OVPNUSERS+1)];

#RANGO DE DIRECCIONES A SER ASIGNADOS A LOS USUARIOS DEL TUNEL.
:global POOLOVPN "10.10.0.$FIRSTHOST-10.10.0.$LASTHOST"

# EDITABLE POR EL TECNICO : Mascara a ser aplicada al cliente OVPN.
:global NETMASK 24



#RESCRIBE LA TABLA DE RUTEO DEL CLIENTE PARA INCLUIRSE COMO RESOLUTOR SECUNDARIO. DISABLED DEFAULT PARA SPLIT TUNNEL.
:if ($ROUTEROSVERSION="V7") do={[:global REDIRECTGATEWAY "disabled"]}


## VARIABLE PARA EL PUSH Y NAT SI SE HABILITA Y ES V7 EN ADELANTE.
:global DSTADDRESS {192.168.0.115;192.168.0.22}

##  (default maybe true to easy) HABILITA LA CREACION DE NATEO PARA EL RANGO $POOLOVPN A $DSTADDRESS OPCIONAL, DE DESEAR NATEO PARA EL SPEECH ENTRE SEGMENTOS.
:global NAT true

#EN TEORIA DEBERIA DE AGREGAR EL ALCANCE A LA RUTA ESPECIFICADA EN EL FORMATO NET MASK GATEWAY METRIC.
:if ($ROUTEROSVERSION="V7") do={[:global PUSHROUTES "$DSTADDRESS"]}

#TIPO DE CIFRADO, EL MÁS ALTO COMPATIBLE POR AMBOS PUNTOS, NO MODIFICARLO DE NO SER NECESARIO.
:global CIPHER "aes256-cbc"

# COMPLEJIDAD DEL CIFRADO PARA LA AUTENTICACION DEL USUARIO, SE RECOMIENDA LA MÁS ALTA COMPATIBLE.
:if ($ROUTEROSVERSION="V7") do={[:global AUTHOVPN "sha512"]} else={[:global AUTHOVPN "sha1"]}











###################################################################################################
###################################################################################################
#                              FIN DE REMPLAZO DE VARIABLES EDITABLES.




## functions
:global waitSec do={:return ($KEYSIZE * 10 / 1024)}

## remove a CA certificate
/certificate
:if ([find name="$CN"]) do={[remove "$CN";:put "REMOVIDO EXISTOSAMENTE";]} else={[:put "TELENET: NO ENCONTRADO";]};
:if ([find name="ca-template"]) do={[remove "ca-template";:put "REMOVIDO EXISTOSAMENTE";]} else={[:put "TELENET: NO ENCONTRADO";]};
:delay [$waitSec]

## remove a server certificate
/certificate
:if ([find name="server-template"]) do={[remove "server-template";:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]};
:if ([find name="server@$CN"]) do={[remove "server@$CN";:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]};
:delay [$waitSec]

## remove a client template
/certificate
:if ([find name="client-template"]) do={[remove "client-template";:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]};
:if ([find name="client-template-to-issue"]) do={[remove "client-template-to-issue";:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]};


## remove a client/s certificate/s.
/certificate
:foreach k,v in=$OVPNUSERS do={[:if ([find name="$k@$CN"]) do={[remove "$k@$CN";:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]}]};



## REMOVE USER/S.
/ppp secret
# remove secret/s. 
:foreach k,v in=$OVPNUSERS do={[:if ([find name=$k&&(profile="VPN-PROFILE-$OVPNPROFILE"|profile="*1")]) do={[remove [find $k&&(profile="VPN-PROFILE-$OVPNPROFILE"|profile="*1")] ;:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]}]}


## remove VPN profile
/ppp profile
:if ([find name="VPN-PROFILE-$OVPNPROFILE"]) do={[remove "VPN-PROFILE-$OVPNPROFILE";:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]};

## remove IP pool
/ip pool
:if ([find name="VPN-POOL-$OVPNPROFILE"]) do={[remove "VPN-POOL-$OVPNPROFILE";:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]};

## setup OpenVPN server
/interface ovpn-server server
set auth="$AUTHOVPN" cipher=$CIPHER default-profile="default" enabled="no" mode=ip netmask=$NETMASK require-client-certificate=yes push-routes=""

## remove a firewall rule
/ip firewall filter
:if ([find comment="Allow-OpenVPN-$OVPNPROFILE"]) do={[remove [find comment="Allow-OpenVPN-$OVPNPROFILE"];:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]};

## remove a firewall NAT
:if ($NAT) do={/ip firewall address-list;:if (([find address="$POOLOVPN"&&list="$OVPNPROFILE-TO-SERVER"])) do={remove [find address="$POOLOVPN"&&list="$OVPNPROFILE-TO-SERVER"]} else={:put "NO EXISTE EL ADDRESSLIST POOLVPN"};/ip firewall nat;:if (([find comment="$OVPNPROFILE-TO-SERVER"])) do={:put "ENTRO EN ELIMINAR NAT RULE";remove [find comment="$OVPNPROFILE-TO-SERVER"&&dst-address-list="$OVPNPROFILE-TO-SERVER"&&src-address-list="$OVPNPROFILE-TO-SERVER"]};:foreach v in=$DSTADDRESS do={:put "ENTRO EN EL FOREACH DE ADRESSLIST PUSHROUTES";/ip firewall address-list;:if (([find where address=$v&&list="$OVPNPROFILE-TO-SERVER"])) do={:put "PUSH ROUTES ADDRESS LIST CREATE";remove [find address=$v&&list="$OVPNPROFILE-TO-SERVER"]} else={:put "ya existe el address list DEL PUSH";}}}


## remove the CA, client certificate, and private key

/file
:if ([find name="cert_export_$CN.crt"]) do={[remove "cert_export_$CN.crt";:put "TL: 'cert_export_$CN.crt' REMOVIDO EXISTOSAMENTE"]} else={[:put "TL: 'cert_export_$CN.crt' NO ENCONTRADO"]};
:foreach k,v in=$OVPNUSERS do={[:if ([find name="cert_export_$k@$CN.crt"]) do={[remove "cert_export_$k@$CN.crt";:put "TL : 'cert_export_$k@$CN.crt' REMOVIDO EXISTOSAMENTE"]} else={[:put "TL: 'cert_export_$k@$CN.crt' NO ENCONTRADO"]};:if ([find name="cert_export_$k@$CN.key"]) do={[remove "cert_export_$k@$CN.key";:put "TL : 'cert_export_$k@$CN.crt' REMOVIDO EXISTOSAMENTE"]} else={[:put "TL: 'cert_export_$k@$CN.crt' NO ENCONTRADO"]};]};
/
:put "TL: FIN DEL PROCESO REMOVE..."
/ 






