#REMOVE OVPN CONFIGURATION SCRIPT DL240410



##############################################################################################################################################################
#               REMPLAZAR ESTE SEGMENTO CON LAS VARIABLES DEL SCRIPT DE CREACION PARA QUE PUEDA LOCALIZAR CORRECTAMENTE LAS CONFIGURACIONES A REMOVER


######## VERSION OR RouterOS. VALUES VALIDS: "V6" OR  "V7"
:global ROUTEROSVERSION "V7"

######## PARAMETROS DEL CA CERTIFICADOR ###############################################################


#################### PARAMETROS PARA LA CREACION DEL TUNEL OVPN ######################################

# IPP DE BORDE POR LA QUE SE ACCEDE AL OVPN SERVER SEA LA IP PUBLICA EJ: 1.1.1.1 (IPP GOOGLE ) DEL MIKROTIK O UNA IP DE UN SEGMENTO EN EL CASO DE SUBSEGMENTOS.
:global SERVERADDRESS "1.1.1.1"



#################### PARAMETROS PARA LA CREACION DEL USUARIO OVPN ######################################

# EDITABLE POR EL TECNICO (OBLIGATORIO):  USUARIO/OS CONTRASEÑA/AS A CREAR, LA CONTRASEÑA DEBE COMPLIR CON EL STANDAR DE COMPLEJIDAD ACTUAL DE MÁS DE 8 CARACTERES ALEATORIO MAYUS MIN CARACTERES ESPECIALES NUMERICOS.
:global OVPNUSERS {"contabilidad1"="AH123";"contabilidad2"="AH123";"contabilidad3"="AH123"}



#################### PARAMETROS PARA LA CREACION DEL PERFIL OVPN SERVER. ######################################

# EDITABLE POR EL TECNICO (OBLIGATORIO):  NOMBRE REPRENTATIVO DEL TUNEL VPN EJ: OVPNMACDONALS 
:global VPNPROFILE "OVPNMACDONALS"

#NO SE RECOMIENDA EDITAR : CALCULA AUTOMATICAMENTE LA CANTIDAD DE HOST DEL POOL VPN CONFORME A LA CANTIDAD DE USUARIOS DECLARADOS EN EL ARRAR $OVPNUSERS.
:global LASTHOST [:len $OVPNUSERS];

#RESCRIBE LA TABLA DE RUTEO DEL CLIENTE PARA INCLUIRSE COMO RESOLUTOR SECUNDARIO. DISABLED DEFAULT PARA SPLIT TUNNEL.
:if ($ROUTEROSVERSION="V7") do={[:global REDIRECTGATEWAY "disabled"]}


#TIPO DE CIFRADO, EL MÁS ALTO COMPATIBLE POR AMBOS PUNTOS, NO MODIFICARLO DE NO SER NECESARIO.
:global CIPHER "aes256-cbc"

# COMPLEJIDAD DEL CIFRADO PARA LA AUTENTICACION DEL USUARIO, SE RECOMIENDA LA MÁS ALTA COMPATIBLE.
:if ($ROUTEROSVERSION="V7") do={[:global AUTHOVPN "sha512"]} else={[:global AUTHOVPN "sha1"]}















##########################################################################################################################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################
##########################################################################################################################################################################
#                                                  FIN DE REMPLAZO DE VARIABLES EDITABLES.




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
:foreach k,v in=$OVPNUSERS do={[:if ([find name=$k&&(profile="VPN-PROFILE-$VPNPROFILE"|profile="*1")]) do={[remove [find $k&&(profile="VPN-PROFILE-$VPNPROFILE"|profile="*1")] ;:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]}]}


## remove VPN profile
/ppp profile
:if ([find name="VPN-PROFILE-$VPNPROFILE"]) do={[remove "VPN-PROFILE-$VPNPROFILE";:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]};

## remove IP pool
/ip pool
:if ([find name="VPN-POOL-$VPNPROFILE"]) do={[remove "VPN-POOL-$VPNPROFILE";:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]};

## setup OpenVPN server
/interface ovpn-server server
set auth="$AUTHOVPN" cipher=$CIPHER default-profile="default" enabled="no" mode=ip netmask=$NETMASK require-client-certificate=yes push-routes=""

## remove a firewall rule
/ip firewall filter
:if ([find comment="Allow-OpenVPN-$VPNPROFILE"]) do={[remove [find comment="Allow-OpenVPN-$VPNPROFILE"];:put "REMOVIDO EXISTOSAMENTE"]} else={[:put "TELENET: NO ENCONTRADO"]};


/file
:if ([find name="cert_export_$CN.crt"]) do={[remove "cert_export_$CN.crt";:put "TL: 'cert_export_$CN.crt' REMOVIDO EXISTOSAMENTE"]} else={[:put "TL: 'cert_export_$CN.crt' NO ENCONTRADO"]};
:foreach k,v in=$OVPNUSERS do={[:if ([find name="cert_export_$k@$CN.crt"]) do={[remove "cert_export_$k@$CN.crt";:put "TL : 'cert_export_$k@$CN.crt' REMOVIDO EXISTOSAMENTE"]} else={[:put "TL: 'cert_export_$k@$CN.crt' NO ENCONTRADO"]};:if ([find name="cert_export_$k@$CN.key"]) do={[remove "cert_export_$k@$CN.key";:put "TL : 'cert_export_$k@$CN.crt' REMOVIDO EXISTOSAMENTE"]} else={[:put "TL: 'cert_export_$k@$CN.crt' NO ENCONTRADO"]};]};
/
:put "TL: FIN DEL PROCESO REMOVE..."




