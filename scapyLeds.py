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


# Logging
archivoLog = "/home/pi/scapyLeds/syslog.txt"
logFlag = "/home/pi/scapyLeds/logging.enabled"
# systemd auxiliares
archivoOperacion = "/home/pi/scapyLeds/scapyLeds.running"
archivoControl = "/ramdisk/LOCK_scapyLeds.txt"


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
GLOBAL_LISTA_PSIZE = deque(maxlen=muestras)
GLOBAL_LISTA_HOSTS = deque(maxlen=muestras)
GLOBAL_LISTA_PORTS = deque(maxlen=muestras)
GLOBAL_LISTA_PPS = deque(maxlen=muestras)
GLOBAL_LISTA_CAPTURAS = deque(maxlen=cantCapturas) #aca voy a guardar las ultimas 10 capturas.
GLOBAL_AVG_PSIZE = 0
GLOBAL_AVG_HOSTS = 0
GLOBAL_AVG_PORTS = 0
GLOBAL_AVG_PPS = 0
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

def scaleMasterA(PSIZE, HOSTS, PORTS, PPS):
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
    # HOSTS - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    # quiero que GLOBAL_AVG_HOSTS sea 1 led prendido. Luego prendo un led adicional...
    #  ... por cada orden de magnitud que supere al promedio
    cantLeds = 0
    if((HOSTS > 0) and (HOSTS < GLOBAL_AVG_HOSTS)):
        cantLeds = 1
    if((HOSTS > GLOBAL_AVG_HOSTS) and (HOSTS < GLOBAL_AVG_HOSTS*2)):
        cantLeds = 2
    if((HOSTS > GLOBAL_AVG_HOSTS*2) and (HOSTS < GLOBAL_AVG_HOSTS*3)):
        cantLeds = 3
    if((HOSTS > GLOBAL_AVG_HOSTS*3) and (HOSTS < GLOBAL_AVG_HOSTS*4) and (HOSTS > 5)):
        cantLeds = 4
    if((HOSTS > GLOBAL_AVG_HOSTS*4) and (HOSTS > 15)):
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

def promedios(pSize, nHosts, nPorts, pps):
    global GLOBAL_LISTA_PSIZE
    global GLOBAL_LISTA_HOSTS
    global GLOBAL_LISTA_PORTS
    global GLOBAL_LISTA_PPS
    global GLOBAL_AVG_PSIZE
    global GLOBAL_AVG_HOSTS
    global GLOBAL_AVG_PORTS
    global GLOBAL_AVG_PPS
    
    GLOBAL_LISTA_PSIZE.append(pSize)
    GLOBAL_LISTA_HOSTS.append(nHosts)
    GLOBAL_LISTA_PORTS.append(nPorts)
    GLOBAL_LISTA_PPS.append(pps)
    GLOBAL_AVG_PSIZE = sum(GLOBAL_LISTA_PSIZE)/len(GLOBAL_LISTA_PSIZE)
    GLOBAL_AVG_HOSTS = sum(GLOBAL_LISTA_HOSTS)/len(GLOBAL_LISTA_HOSTS)
    GLOBAL_AVG_PORTS = sum(GLOBAL_LISTA_PORTS)/len(GLOBAL_LISTA_PORTS)
    GLOBAL_AVG_PPS = sum(GLOBAL_LISTA_PPS)/len(GLOBAL_LISTA_PPS)

# --------------------------------------------------------------

def dibujarDEBUG(valRow0, valRow1, valRow2, valRow3):
    clear = lambda: os.system('clear')
    clear()
    linea0 = ""
    linea1 = ""
    linea2 = ""
    linea3 = ""
    for i in range(valRow0):
        linea0 = linea0 + "@   "
    for i in range(valRow1):
        linea1 = linea1 + "@   "
    for i in range(valRow2):
        linea2 = linea2 + "@   "
    for i in range(valRow3):
        linea3 = linea3 + "@   "
    print(linea0)
    print(linea1)
    print(linea2)
    print(linea3)




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
    count = len(listaManojo)
    avg_size = total_size / count if count > 0 else 0
    # promedios(pSize, nHosts, nPorts, pps)
    promedios(avg_size, len(ip_set), len(tcp_ports)+len(udp_ports), count/TIEMPO_CAPTURA*cantCapturas)
    return {
        "packet_count": count,
        "avg_packet_size": avg_size,
        "unique_hosts": len(ip_set),
        "tcp_ports": len(tcp_ports),
        "udp_ports": len(udp_ports),
    }


# --------------------------------------------------------------


def analyze_list_bkp():
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
    for packets in GLOBAL_LISTA_CAPTURAS:
        for pkt in packets:
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
        count = count + len(packets)
        avg_size = total_size / count if count > 0 else 0
    # promedios(pSize, nHosts, nPorts, pps)
    promedios(avg_size, len(ip_set), len(tcp_ports)+len(udp_ports), count/TIEMPO_CAPTURA*cantCapturas)
    return {
        "packet_count": count,
        "avg_packet_size": avg_size,
        "unique_hosts": len(ip_set),
        "tcp_ports": len(tcp_ports),
        "udp_ports": len(udp_ports),
    }




# --------------------------------------------------------------



def analyze_packets(packets):
    total_size = 0
    ip_set = set()
    tcp_ports = set()
    udp_ports = set()

    for pkt in packets:
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
    count = len(packets)
    avg_size = total_size / count if count > 0 else 0
    promedios(avg_size, len(ip_set), len(tcp_ports)+len(udp_ports), count/TIEMPO_CAPTURA)
    return {
        "packet_count": count,
        "avg_packet_size": avg_size,
        "unique_hosts": len(ip_set),
        "tcp_ports": len(tcp_ports),
        "udp_ports": len(udp_ports),
    }


# --------------------------------------------------------------

def capture_loop(interface='eth0'):
    global GLOBAL_LISTA_CAPTURAS
    global queueDibujo
    row0_prev = 0
    row1_prev = 0
    row2_prev = 0
    row3_prev = 0
    row0 = None
    row1 = None
    row2 = None
    row3 = None

    while True:
        start = time.time()
        packets = sniff(iface=interface, timeout=TIEMPO_CAPTURA)  # 100ms window
        GLOBAL_LISTA_CAPTURAS.append(packets)
        # stats = analyze_packets(packets)
        stats = analyze_list()
        elapsed = time.time() - start
        pps = stats["packet_count"] / elapsed if elapsed > 0 else 0
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
        row0, row1, row2, row3 = scaleMasterA(stats["avg_packet_size"], stats["unique_hosts"], stats["tcp_ports"]+stats["udp_ports"], round(pps, 2))
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
            # dibujarDEBUG(row0_prev,row1_prev,row2_prev,row3_prev)
        ahoraTest = time.time()
        msTranscurridos = (ahoraTest - start)*1000
        debieraSer = TIEMPO_CAPTURA * 1000
        relativo = int(msTranscurridos * 100 / debieraSer)





# --------------------------------------------------------------


def main():
    p1 = multiprocessing.Process(target=dibujarMP, args=(queueDibujo,))
    p1.start()
    try:
        while(True):
            capture_loop()
    except KeyboardInterrupt:
        queueDibujo.put((-9,0,0,0))
        time.sleep(2)
        sys.exit()


main()
GPIO.cleanup()