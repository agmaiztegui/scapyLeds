from scapy.all import sniff, IP, TCP, UDP, AsyncSniffer
import time
from datetime import datetime
from scapy.all import AsyncSniffer
from collections import defaultdict, deque
import threading
import RPi.GPIO as GPIO
import multiprocessing
import subprocess
import queue
import os
# systemd version
import sys
# cosas http
import re
from collections import Counter

# Logging
archivoLog = "/home/pi/scapyLeds/syslog.txt"
logFlag = "/home/pi/scapyLeds/logging.enabled"
# systemd auxiliares
archivoOperacion = "/home/pi/scapyLeds/scapyLeds.running"
archivoControl = "/ramdisk/LOCK_scapyLeds.txt"
systemEnabled = 1

# TIEMPO_CAPTURA = 0.05
TIEMPO_CAPTURA = 0.05
# 0.15 se hacen 170 - 200 %
# 0.05 se hacen 260 - 400 % !!!
# GPIO.setwarnings(False) 
GPIO.setmode(GPIO.BCM)
#
stripON = 0.001
# refreshes = 8
refreshes = 8
#
row0 = 26
row1 = 6
row2 = 27
row3 = 22

col0 = 12
col1 = 25
col2 = 24
col3 = 23 #
col4 = 18 #


# variables HTTP method
RE_HTTP_METHOD = re.compile(rb'^(GET|POST|HEAD|OPTIONS|PUT|DELETE)\s+', re.I)
WEIGHTS = {
    b"GET": 1.0,
    b"HEAD": 0.8,
    b"OPTIONS": 0.5,
    b"POST": 1.5,    # POSTs often indicate login attempts / brute force
    b"PUT": 1.5,
    b"DELETE": 3.0,
}






try:
    GPIO.cleanup()
    GPIO.setmode(GPIO.BCM)
except Exception as e:
    print("GPIO no en uso")

# print(scapy.__version__)

#
GPIO.setup(row0, GPIO.OUT)
GPIO.setup(row1, GPIO.OUT)
GPIO.setup(row2, GPIO.OUT)
GPIO.setup(row3, GPIO.OUT)
#
GPIO.setup(col0, GPIO.OUT)
GPIO.setup(col1, GPIO.OUT)
GPIO.setup(col2, GPIO.OUT)
GPIO.setup(col3, GPIO.OUT)
GPIO.setup(col4, GPIO.OUT)
#
# AVERAGING & SCALING
muestras = 150
cantCapturas = 6
GLOBAL_LISTA_PSIZE = deque(maxlen=5)
GLOBAL_LISTA_HTTPMETHODS = deque(maxlen=muestras*10)
GLOBAL_LISTA_HTTPMETHODS_SMALL = deque(maxlen=15)
GLOBAL_LISTA_PORTS = deque(maxlen=muestras)
GLOBAL_LISTA_PPS = deque(maxlen=muestras)
GLOBAL_LISTA_CAPTURAS = deque(maxlen=cantCapturas) #aca voy a guardar las ultimas 10 capturas.
GLOBAL_AVG_PSIZE = 0
GLOBAL_AVG_HTTP = 0
GLOBAL_AVG_PORTS = 0
GLOBAL_AVG_PPS = 0
GLOBAL_AVG_HTTP_SMALL = 0
queueDibujo = multiprocessing.Queue()














###################################################################################################

### 1. Operation check ###

if os.path.exists(archivoOperacion):
    print("scapyLeds is Enabled. Proceeding...")
else:
    print("scapyLeds is DISABLED. Operation Flag not found.")
    sys.exit("File must be present. Check "+archivoOperacion)




###################################################################################################



def loguear(texto):
    global archivoLog
    ahora = datetime.now()
    elStamp = ahora.strftime("%d/%m/%Y %H:%M:%S - ")
    escribir = elStamp + texto + "\n"
    try:
        if os.path.exists(logFlag):
            elArchivo = open(archivoLog, "a")
            elArchivo.write(escribir)
            elArchivo.close()
            return 0
    except:
        print("problema para abrir o escribir el archivo de syslog (!)")
        return -1




###################################################################################################



### 2. SINGLETON ###
if os.path.exists(archivoControl):
    print("File exists! No need to run")
    luzVerde = 0
else:
    print("File not found! Attempting to generate the Lock file...")
    loguear("Starting scapyLeds.py . . .")
    loguear("File not found! Attempting to generate the Lock file...")
    try:
        NewArchivoControl = open(archivoControl,"w")
        NewArchivoControl.close
        luzVerde = 1
    except IOError:
        luzVerde = 0
        
# Si luzVerde == 1 le doy para adelante. Sino finalizo.
if (luzVerde == 0):
    sys.exit("Sript already running!. Check "+archivoControl)
    
# DEBUG! para usar en development
# os.remove(archivoControl)






###################################################################################################


# ejecutar con sudo. Probar de armar otra funcion que se ejecute en simultaneo, que use timeouts mas largos (2 segundos?). Luego hacer un merge ó no de los datos. La idea es poder distinguir entre nmap -T2 de -T3

# --------------------------------------------------------------
# --------------------------------------------------------------

# ¿y si iteración a iteración voy RESTANDO / SUMANDO a los MIN/MAX para "apasiguarlos" y los uso de referencia ?


# --------------------------------------------------------------

def scaleMasterA(PSIZE, WEIGHT_RATIO, PORTS, PPS):
    # tengo min, max, gajos y leds para el promedio.
    display = []
    
    # PSIZE - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # quiero que ~1500 bytes sean 4 leds prendidos.
    cantLeds = 0
    if((PSIZE > 0) and (PSIZE < 96)):
        cantLeds = 1
    if((PSIZE > 96) and (PSIZE < 500)):
        cantLeds = 2
    if((PSIZE > 500) and (PSIZE < 1000)):
        cantLeds = 3
    if((PSIZE > 1000) and (PSIZE < 1550)):
        cantLeds = 4
    if(PSIZE > 1550 ):
        cantLeds = 5
    display.append(cantLeds)
    # HTTP Methods - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    LOCAL_WEIGHT_RATIO_AVR = GLOBAL_AVG_HTTP / (TIEMPO_CAPTURA*cantCapturas)
    LOCAL_WEIGHT_RATIO_AVR_SMALL = GLOBAL_AVG_HTTP_SMALL / (TIEMPO_CAPTURA*cantCapturas)
    if(LOCAL_WEIGHT_RATIO_AVR != 0):
        frase = "AVR_SMALL={2:.1f}  WRR={0:.1f}  LWR={1:1f}".format(WEIGHT_RATIO / LOCAL_WEIGHT_RATIO_AVR, LOCAL_WEIGHT_RATIO_AVR, LOCAL_WEIGHT_RATIO_AVR_SMALL)
        loguear(frase)
    cantLeds = 0
    weight_1led = LOCAL_WEIGHT_RATIO_AVR
    weight_2leds = LOCAL_WEIGHT_RATIO_AVR * 1.5
    weight_3leds = LOCAL_WEIGHT_RATIO_AVR * 1.9
    weight_4leds = LOCAL_WEIGHT_RATIO_AVR * 2.5
    if((LOCAL_WEIGHT_RATIO_AVR_SMALL > 0) and (LOCAL_WEIGHT_RATIO_AVR_SMALL < weight_1led)):
        cantLeds = 1
    if((LOCAL_WEIGHT_RATIO_AVR_SMALL > weight_1led) and (LOCAL_WEIGHT_RATIO_AVR_SMALL < weight_2leds)):
        cantLeds = 2
    if((LOCAL_WEIGHT_RATIO_AVR_SMALL > weight_2leds) and (LOCAL_WEIGHT_RATIO_AVR_SMALL < weight_3leds)):
        cantLeds = 3
    if((LOCAL_WEIGHT_RATIO_AVR_SMALL > weight_3leds) and (LOCAL_WEIGHT_RATIO_AVR_SMALL < weight_4leds)):
        cantLeds = 4
    if(LOCAL_WEIGHT_RATIO_AVR_SMALL > weight_4leds):
        cantLeds = 5
    display.append(cantLeds)
    # PORTS - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # quiero que GLOBAL_AVG_PORTS sea 1 led prendido. Luego prendo un led adicional...
    #  ... por cada orden de magnitud que supere al promedio
    cantLeds = 0
    prom_ports = GLOBAL_AVG_PORTS
    if(prom_ports < 5):
        prom_ports = 5
    if((PORTS > 0) and (PORTS < prom_ports)):
        cantLeds = 1
    if((PORTS > prom_ports) and (PORTS < prom_ports*2.5)):
        cantLeds = 2
    if((PORTS > prom_ports*2.5) and (PORTS < prom_ports*3)):
        cantLeds = 3
    if((PORTS > prom_ports*3) and (PORTS < prom_ports*3.5) and (PORTS > 5)):
        cantLeds = 4
    if((PORTS > prom_ports*3.5) and (PORTS > 15)):
        cantLeds = 5
    display.append(cantLeds)
    # PPS - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # quiero que GLOBAL_AVG_PPS sea 1 led prendido. Luego prendo un led adicional...
    #  ... por cada orden de magnitud que supere al promedio
    cantLeds = 0
    if((PPS > 0) and (PPS < GLOBAL_AVG_PPS)):
        cantLeds = 1
    if((PPS > GLOBAL_AVG_PPS) and (PPS < GLOBAL_AVG_PPS*2)):
        cantLeds = 2
    if((PPS > GLOBAL_AVG_PPS*2) and (PPS < GLOBAL_AVG_PPS*3)):
        cantLeds = 3
    if((PPS > GLOBAL_AVG_PPS*3) and (PPS < GLOBAL_AVG_PPS*4) and (PPS > 5)):
        cantLeds = 4
    if((PPS > GLOBAL_AVG_PPS*4) and (PPS > 15)):
        cantLeds = 5
    display.append(cantLeds)
    return display
  
    
# --------------------------------------------------------------

def promedios(pSize, weights_http_methods, nPorts, pps):
    global GLOBAL_LISTA_PSIZE
    global GLOBAL_LISTA_HTTPMETHODS
    global GLOBAL_LISTA_HTTPMETHODS_SMALL
    global GLOBAL_LISTA_PORTS
    global GLOBAL_LISTA_PPS
    global GLOBAL_AVG_PSIZE
    global GLOBAL_AVG_HTTP
    global GLOBAL_AVG_PORTS
    global GLOBAL_AVG_PPS
    global GLOBAL_AVG_HTTP_SMALL
    
    GLOBAL_LISTA_PSIZE.append(pSize)
    GLOBAL_LISTA_HTTPMETHODS_SMALL.append(weights_http_methods)
    if(weights_http_methods > 0.05):
        GLOBAL_LISTA_HTTPMETHODS.append(weights_http_methods)
    GLOBAL_LISTA_PORTS.append(nPorts)
    GLOBAL_LISTA_PPS.append(pps)
    
    if(len(GLOBAL_LISTA_HTTPMETHODS)>0):
        GLOBAL_AVG_HTTP = sum(GLOBAL_LISTA_HTTPMETHODS)/len(GLOBAL_LISTA_HTTPMETHODS)
    else:
        GLOBAL_AVGGLOBAL_LISTA_HTTPMETHODS_SMALL_HTTP = 0.0
    
    GLOBAL_AVG_HTTP_SMALL = sum(GLOBAL_LISTA_HTTPMETHODS_SMALL)/len(GLOBAL_LISTA_HTTPMETHODS_SMALL)
    GLOBAL_AVG_PSIZE = sum(GLOBAL_LISTA_PSIZE)/len(GLOBAL_LISTA_PSIZE)
    GLOBAL_AVG_PORTS = sum(GLOBAL_LISTA_PORTS)/len(GLOBAL_LISTA_PORTS)
    GLOBAL_AVG_PPS = sum(GLOBAL_LISTA_PPS)/len(GLOBAL_LISTA_PPS)

# --------------------------------------------------------------


# --------------------------------------------------------------


def dibujarMP(laQueue):
    anterior = None
    actual = None
    # NECESITO estos valores: (valRow0, valRow1, valRow2, valRow3)
    # me los pueden mandar asi: unaQueue.put((1, 2, 5, 3))
    # los saco del queue, SI HAY.
        # Si no hay, uso el valor ANTERIOR.
            # Si no hay valor anterior, ESPERO!
    flagRUN = 1
    
    while(flagRUN):
        try:
            actual = laQueue.get_nowait()
            anterior = actual
        except queue.Empty:
            # time.sleep(0.01)
            actual = anterior
        #
        # if(not laQueue.empty):
        if(actual != None):
            valRow0, valRow1, valRow2, valRow3 = actual
        else:
            valRow0, valRow1, valRow2, valRow3 = (0,0,0,0)
        if(valRow0 == -9):
            flagRUN = 0
            # loguear("dibujarMP: recibí kill signal.")
        
        # 1º apago TODO.
        for x in range(refreshes):
            setearPINS(1,1,1,1, 0,0,0,0,0) # cero volts en COLs, 3.3 volts en ROWs (al reves del diodo!)
            setearPINS(0,0,0,0, 0,0,0,0,0) # cero volts en COLs, cero volts en ROWs.
            # SEGUNDO PROTOTIPO: negativos en las ROWS, positivos en las COLS. ejemplo:
            # (0,0,0,0, 0,0,0,0,1): rows todas en 0V, COLUMNA 4 (la ultima) en 3.3V
                # eso hace que prenda TODA la COL4.
            # (1,1,1,0, 0,0,0,0,1): rows0-2 en 1V, ROW3 en 0V. COLUMNA 4 (la ultima) en 3.3V
                # de toda la COL4 que está en 3.3V, solo puede circular al 0V de la ROW3.
                # prende SOLO el LED que está en ROW3 y COL4.
            
            
            # valRowX: cuantos LEDs prendo (de izquierda a derecha) de la ROWX. Numero de 0 a 5 leds.
            # ROW0
            # cuantos LEDs prendo?
            if(valRow0 == 5):
                setearPINS(0,1,1,1, 1,1,1,1,1)
            if(valRow0 == 4):
                setearPINS(0,1,1,1, 1,1,1,1,0)
            if(valRow0 == 3):
                setearPINS(0,1,1,1, 1,1,1,0,0)
            if(valRow0 == 2):
                setearPINS(0,1,1,1, 1,1,0,0,0)
            if(valRow0 == 1):
                setearPINS(0,1,1,1, 1,0,0,0,0)
            if(valRow0 > 0):
                # al menos UN Led tuve que prender. No espero.
                time.sleep(stripON)
            #
            if(valRow1 == 5):
                setearPINS(1,0,1,1, 1,1,1,1,1)
            if(valRow1 == 4):
                setearPINS(1,0,1,1, 1,1,1,1,0)
            if(valRow1 == 3):
                setearPINS(1,0,1,1, 1,1,1,0,0)
            if(valRow1 == 2):
                setearPINS(1,0,1,1, 1,1,0,0,0)
            if(valRow1 == 1):
                setearPINS(1,0,1,1, 1,0,0,0,0)
            if(valRow1 > 0):
                # al menos UN Led tuve que prender. No espero.
                time.sleep(stripON)
            #
            if(valRow2 == 5):
                setearPINS(1,1,0,1, 1,1,1,1,1)
            if(valRow2 == 4):
                setearPINS(1,1,0,1, 1,1,1,1,0)
            if(valRow2 == 3):
                setearPINS(1,1,0,1, 1,1,1,0,0)
            if(valRow2 == 2):
                setearPINS(1,1,0,1, 1,1,0,0,0)
            if(valRow2 == 1):
                setearPINS(1,1,0,1, 1,0,0,0,0)
            if(valRow2 > 0):
                # al menos UN Led tuve que prender. No espero.
                time.sleep(stripON)
            #
            if(valRow3 == 5):
                setearPINS(1,1,1,0, 1,1,1,1,1)
            if(valRow3 == 4):
                setearPINS(1,1,1,0, 1,1,1,1,0)
            if(valRow3 == 3):
                setearPINS(1,1,1,0, 1,1,1,0,0)
            if(valRow3 == 2):
                setearPINS(1,1,1,0, 1,1,0,0,0)
            if(valRow3 == 1):
                setearPINS(1,1,1,0, 1,0,0,0,0)
            if(valRow3 > 0):
                # al menos UN Led tuve que prender.
                time.sleep(stripON)
            #
 
 
# --------------------------------------------------------------

def setearPINS(cval0, cval1, cval2, cval3, rval0, rval1, rval2, rval3, rval4):
    # intento para eliminar el fantasmeo.
    GPIO.output(row0, 1) 
    GPIO.output(row1, 1)
    GPIO.output(row2, 1)
    GPIO.output(row3, 1)
    #
    GPIO.output(col0, 0)
    GPIO.output(col1, 0)
    GPIO.output(col2, 0)
    GPIO.output(col3, 0)
    GPIO.output(col4, 0)    
    
    time.sleep(stripON)
    # Ahora sí, dibujo lo que me pidieron.
    
    GPIO.output(row0, cval0) 
    GPIO.output(row1, cval1)
    GPIO.output(row2, cval2)
    GPIO.output(row3, cval3)
    #
    GPIO.output(col0, rval0)
    GPIO.output(col1, rval1)
    GPIO.output(col2, rval2)
    GPIO.output(col3, rval3)
    GPIO.output(col4, rval4)



# --------------------------------------------------------------


# --------------------------------------------------------------

def analyze_list():
    global GLOBAL_LISTA_CAPTURAS
    total_size = 0
    ip_set = set()
    tcp_ports = set()
    udp_ports = set()
    count = 0

    listaManojo = []
    for packets in GLOBAL_LISTA_CAPTURAS:
        for pkt in packets:
            listaManojo.append(pkt)
    # --- HTTP method counting ---
    method_counter = Counter()
    weighted_sum = 0.0
    for pkt in listaManojo:
        total_size += len(pkt)
        if IP in pkt:
            ip_set.add(pkt[IP].src)
            ip_set.add(pkt[IP].dst)
        if TCP in pkt:
            tcp_ports.add(pkt[TCP].sport)
            tcp_ports.add(pkt[TCP].dport)
        if UDP in pkt:
            udp_ports.add(pkt[UDP].sport)
            udp_ports.add(pkt[UDP].dport)
        

        # métodos http
        if pkt.haslayer('Raw'):
            try:
                payload = bytes(pkt['Raw'].load)
            except Exception as e:
                payload = b''
            if not payload:
                continue
            # loguear(str(repr(payload[:64])))
            m = RE_HTTP_METHOD.search(payload[:64])
            if m:
                # loguear("encontre metodos http.")
                method = m.group(1).upper()
                method_counter[method] += 1
                weighted_sum += WEIGHTS.get(method, 1.0)
            
            
    count = len(listaManojo)
    avg_size = total_size / count if count > 0 else 0
    # promedios(pSize, weights_http_methods, nPorts, pps)
    promedios(avg_size, weighted_sum, len(tcp_ports)+len(udp_ports), count/TIEMPO_CAPTURA*cantCapturas)
    return {
        "packet_count": count,
        "avg_packet_size": avg_size,
        "unique_hosts": len(ip_set),
        "tcp_ports": len(tcp_ports),
        "udp_ports": len(udp_ports),
        "weighted_sum": weighted_sum,
    }


# --------------------------------------------------------------

# --------------------------------------------------------------

# --------------------------------------------------------------

# --------------------------------------------------------------

def capture_loop(interface='eth0'):
    global GLOBAL_LISTA_CAPTURAS
    global queueDibujo
    global systemEnabled
    
    row0_prev = 0
    row1_prev = 0
    row2_prev = 0
    row3_prev = 0
    row0 = None
    row1 = None
    row2 = None
    row3 = None
    
    contador = 0

    while (systemEnabled == 1):
        start = time.time()
        packets = sniff(iface=interface, timeout=TIEMPO_CAPTURA)  # 100ms window
        GLOBAL_LISTA_CAPTURAS.append(packets)
        stats = analyze_list()
        elapsed = time.time() - start
        pps = stats["packet_count"] / elapsed if elapsed > 0 else 0
        weight_ratio = stats["weighted_sum"] / elapsed if elapsed > 0 else 0
        if((row0 != None) and (row1 != None) and (row2 != None) and (row3 != None)):
            row0_prev = row0
            row1_prev = row1
            row2_prev = row2
            row3_prev = row3
        else:
            row0_prev = 0
            row1_prev = 0
            row2_prev = 0
            row3_prev = 0
        row0, row1, row2, row3 = scaleMasterA(stats["avg_packet_size"], weight_ratio, stats["tcp_ports"]+stats["udp_ports"], round(pps, 2))
        # Voy a agregar a la Queue tantos cambios como hagan falta para incrementar leds DE A UNO!
        dif_row0 = row0 - row0_prev
        dif_row1 = row1 - row1_prev
        dif_row2 = row2 - row2_prev
        dif_row3 = row3 - row3_prev
        while((row0_prev != row0) or (row1_prev != row1) or (row2_prev != row2) or (row3_prev != row3)):
            if((dif_row0 > 0) and (row0_prev != row0)):
                row0_prev = row0_prev + 1
            if((dif_row0 < 0) and (row0_prev != row0)):
                row0_prev = row0_prev - 1
            #
            if((dif_row1 > 0) and (row1_prev != row1)):
                row1_prev = row1_prev + 1
            if((dif_row1 < 0) and (row1_prev != row1)):
                row1_prev = row1_prev - 1
            #
            if((dif_row2 > 0) and (row2_prev != row2)):
                row2_prev = row2_prev + 1
            if((dif_row2 < 0) and (row2_prev != row2)):
                row2_prev = row2_prev - 1
            #
            if((dif_row3 > 0) and (row3_prev != row3)):
                row3_prev = row3_prev + 1
            if((dif_row3 < 0) and (row3_prev != row3)):
                row3_prev = row3_prev - 1
            #
            # Agrego el dibujo intermedio con los row0_prev
            queueDibujo.put((row0_prev,row1_prev,row2_prev,row3_prev))
        ahoraTest = time.time()
        msTranscurridos = (ahoraTest - start)*1000
        debieraSer = TIEMPO_CAPTURA * 1000
        relativo = int(msTranscurridos * 100 / debieraSer)
        # checkeo condicion de salida
        contador = contador + 1
        if(contador > 55):
            # debiera ser 5 segundos con 55 loops, aprox.
            contador = 0
            if os.path.exists(archivoOperacion):
                pass
            else:
                systemEnabled = 0
                queueDibujo.put((-9,0,0,0)) # mando un software kill signal al otro proceso.
                loguear("mande kill signal a dibujarMP.")
    loguear("captureLoop finalizó.")




# --------------------------------------------------------------


def main():
    global systemEnabled
    p1 = multiprocessing.Process(target=dibujarMP, args=(queueDibujo,))
    p1.start()
    loguear("inicio!")
    
    
    try:
        while(systemEnabled == 1):
            capture_loop()
    except KeyboardInterrupt:
        queueDibujo.put((-9,0,0,0))
        time.sleep(2)
        loguear("Keyboard interrupt!")
        sys.exit()
    loguear("MAIN finalizó.")


main()
try:
    GPIO.cleanup()
except Exception as e:
    print(e)
    # loguear(str(e))
time.sleep(2)
os.remove(archivoControl)
print("END.")
loguear("END.")

sys.exit(0)
